/*
 * Copyright (C) 2017 Martin Paljak
 */

#include "qwincrypt.h"

#ifdef Q_OS_WIN

#include "debuglog.h"

#include <WinError.h>
#include <ncrypt.h>
#include <WinCrypt.h>
#include <cryptuiapi.h>


extern "C" {

    typedef BOOL(WINAPI * PFNCCERTDISPLAYPROC)(
        __in  PCCERT_CONTEXT pCertContext,
        __in  HWND hWndSelCertDlg,
        __in  void *pvCallbackData
    );

    typedef struct _CRYPTUI_SELECTCERTIFICATE_STRUCT {
        DWORD               dwSize;
        HWND                hwndParent;
        DWORD               dwFlags;
        LPCWSTR             szTitle;
        DWORD               dwDontUseColumn;
        LPCWSTR             szDisplayString;
        PFNCFILTERPROC      pFilterCallback;
        PFNCCERTDISPLAYPROC pDisplayCallback;
        void *              pvCallbackData;
        DWORD               cDisplayStores;
        HCERTSTORE *        rghDisplayStores;
        DWORD               cStores;
        HCERTSTORE *        rghStores;
        DWORD               cPropSheetPages;
        LPCPROPSHEETPAGEW   rgPropSheetPages;
        HCERTSTORE          hSelectedCertStore;
    } CRYPTUI_SELECTCERTIFICATE_STRUCT, *PCRYPTUI_SELECTCERTIFICATE_STRUCT;

    typedef const CRYPTUI_SELECTCERTIFICATE_STRUCT
    *PCCRYPTUI_SELECTCERTIFICATE_STRUCT;

    PCCERT_CONTEXT WINAPI CryptUIDlgSelectCertificateW(
        __in  PCCRYPTUI_SELECTCERTIFICATE_STRUCT pcsc
    );

#define CryptUIDlgSelectCertificate CryptUIDlgSelectCertificateW

}  // extern "C"


// TODO UX: this is a slow operation, possibly skip it and let Windows do the job
static BOOL isCardInReader(PCCERT_CONTEXT certContext) {
    return TRUE;
    //DWORD flags = CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG;
    DWORD flags = CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG;
    NCRYPT_KEY_HANDLE key = 0;
    DWORD spec = 0;
    BOOL ncrypt = FALSE;
    BOOL haskey = CryptAcquireCertificatePrivateKey(certContext, flags, 0, &key, &spec, &ncrypt);
    if (!haskey) {
        _log("Can not acquire key: 0x%08x", GetLastError());
        return FALSE;
    }
    if (!key) {
        return FALSE;
    }
    if (ncrypt) {
        NCryptFreeObject(key);
    }
    _log("Key available");
    return TRUE;
}

QWinCrypt::ErroredResponse QWinCrypt::getCertificates() {
    QList<QByteArray> result;
    HCERTSTORE store = CertOpenSystemStore(0, L"MY");
    if (!store) {
        _log("Cold not open store: 0x%08x", GetLastError());
        return {CKR_GENERAL_ERROR};
    }

    // Enumerate certificates, so that no_certificates satus could be reported.
    PCCERT_CONTEXT cert = nullptr;
    while (cert = CertEnumCertificatesInStore(store, cert)) {
        if (isCardInReader(cert)) {
            result.append(QByteArray((const char *)cert->pbCertEncoded, int(cert->cbCertEncoded)));
        }
    }
    if (cert) {
        CertFreeCertificateContext(cert);
    }
    _log("Found a total of %d certs with a present key in MY store", result.size());
    CertCloseStore(store, 0);
    return {CKR_OK, result};
}


static bool hasClientSSL(PCCERT_CONTEXT certContext) {
    std::vector<unsigned char> exts(sizeof(CERT_ENHKEY_USAGE));
    DWORD usages = 1; // size reporting does not work if initial size is 0 ...
    BOOL enh = CertGetEnhancedKeyUsage(certContext, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, NULL, &usages);
    // FIXME: return code check
    exts.resize(usages);
    enh = CertGetEnhancedKeyUsage(certContext, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, (PCERT_ENHKEY_USAGE) &exts[0], &usages);
    // FIXME: return code check
    PCERT_ENHKEY_USAGE ug = (PCERT_ENHKEY_USAGE) &exts[0];

    for (DWORD i = 0; i < ug->cUsageIdentifier; i++ ) {
        // 1.3.6.1.3.5.5.7.3.2
        if (strcmp(ug->rgpszUsageIdentifier[i], szOID_PKIX_KP_CLIENT_AUTH) == 0) {
            // this is authentication cert
            _log("This is Client SSL cert!");
            return true;
        }
    }
    return false;
}

static bool hasNonRepudiation(PCCERT_CONTEXT certContext) {
    // Check for nonrepudiation bit
    BYTE keyUsage;
    CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certContext->pCertInfo, &keyUsage, 1);
    if (keyUsage & CERT_NON_REPUDIATION_KEY_USAGE) {
        _log("This is NonRepudiation cert!");
        return true;
    }
    return false;
}

static bool isTimeValid(PCCERT_CONTEXT certContext) {
    if (CertVerifyTimeValidity(NULL, certContext->pCertInfo) != 0) {
        _log("Not valid (time)");
        return false;
    }
    return true;
}


static bool isValidAuthenticationCert(PCCERT_CONTEXT certContext) {
    return hasClientSSL(certContext) && isTimeValid(certContext) && isCardInReader(certContext);
}

BOOL WINAPI filter_auth(PCCERT_CONTEXT certContext, BOOL *pfInitialSelectedCert, void *pvCallbackData) {
    // silence C4100 warnings
    (void) pfInitialSelectedCert;
    (void) pvCallbackData;
    _log("Checking certificate for authentication");
    return isValidAuthenticationCert(certContext);
}

static bool isValidSigningCert(PCCERT_CONTEXT certContext) {
    return hasNonRepudiation(certContext) && isTimeValid(certContext) && isCardInReader(certContext);
}

BOOL WINAPI filter_sign(PCCERT_CONTEXT certContext, BOOL *pfInitialSelectedCert, void *pvCallbackData) {
    // silence C4100 warnings
    (void) pfInitialSelectedCert;
    (void) pvCallbackData;
    _log("Checking certificate for signing");
    return isValidSigningCert(certContext);
}

// Show a certificate selection window
QWinCrypt::ErroredResponse QWinCrypt::selectCertificate(CertificatePurpose type, const QString &title, const QString &message, const HWND parent) {

    HCERTSTORE store = CertOpenSystemStore(0, L"MY");
    if (!store)	{
        _log("Cold not open store: %d", GetLastError());
        return {CKR_GENERAL_ERROR};
    }

    // Enumerate certificates, so that no_certificates satus could be reported.
    PCCERT_CONTEXT cert = nullptr;
    int certificatesCount = 0;
    while (cert = CertEnumCertificatesInStore(store, cert)) {
        _log("Checking certificate during enumeration");
        if (type == Signing ? isValidSigningCert(cert) : isValidAuthenticationCert(cert)) {
            certificatesCount++;
        }
    }
    if (cert) {
        CertFreeCertificateContext(cert);
    }
    _log("Found a total of certs in MY store: %d for %d", certificatesCount, type);

    // TODO: what do do with pkcs11 cards and capi cards mixed?
    if (certificatesCount == 0) {
        //CertCloseStore(store, 0);
        //return {CKR_KEY_NEEDED};
    }
    // Show selection dialog
    CRYPTUI_SELECTCERTIFICATE_STRUCT pcsc = { sizeof(pcsc) };
    if (type == Authentication) {
        pcsc.pFilterCallback = filter_auth;
    } else if (type == Signing) {
        pcsc.pFilterCallback = filter_sign;
    }
    // pcsc.dwFlags = CRYPTUI_SELECTCERT_PUT_WINDOW_TOPMOST; Windows 7 sp1 onwards, not available
    pcsc.szTitle = LPWSTR(title.utf16());
    pcsc.hwndParent = parent;
    pcsc.szDisplayString = LPWSTR(message.utf16());
    pcsc.pvCallbackData = nullptr; // TODO: use a single callback with arguments instead ?
    pcsc.cDisplayStores = 1;
    pcsc.rghDisplayStores = &store;
    PCCERT_CONTEXT cert_context = CryptUIDlgSelectCertificate(&pcsc);

    if (!cert_context)
    {
        CertCloseStore(store, 0);
        _log("User pressed cancel");
        return {CKR_FUNCTION_CANCELED};
    }
    QByteArray result = QByteArray((const char *)cert_context->pbCertEncoded, int(cert_context->cbCertEncoded));
    _log("Selected certificate");
    CertFreeCertificateContext(cert_context);
    CertCloseStore(store, 0);
    return {CKR_OK, {result}};
}

QWinCrypt::ErroredResponse QWinCrypt::sign(const QByteArray &cert, const QByteArray &hash, const HashType hashtype, const HWND parent) {
    _log("Cert for signing is: %s", qPrintable(cert.toHex()));
    QByteArray result;
    CK_RV rv = CKR_OK;
    BCRYPT_PKCS1_PADDING_INFO padInfo;
    DWORD obtainKeyStrategy = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG;

    ALG_ID alg = 0;

    switch (hash.size())
    {
    case BINARY_SHA224_LENGTH:
        padInfo.pszAlgId = L"SHA224";
        obtainKeyStrategy = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;
        break;
    case BINARY_SHA256_LENGTH:
        padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
        alg = CALG_SHA_256;
        break;
    case BINARY_SHA384_LENGTH:
        padInfo.pszAlgId = NCRYPT_SHA384_ALGORITHM;
        alg = CALG_SHA_384;
        break;
    case BINARY_SHA512_LENGTH:
        padInfo.pszAlgId = NCRYPT_SHA512_ALGORITHM;
        alg = CALG_SHA_512;
        break;
    default:
        return {CKR_ARGUMENTS_BAD};
    }

    SECURITY_STATUS err = 0;
    DWORD size = 256; // FIXME use NULL and resize accordingly
    result.resize(size);

    HCERTSTORE store = CertOpenSystemStore(0, L"MY");
    if (!store) {
        _log("Could not open MY store"); // TODO lasterror
        return {CKR_GENERAL_ERROR};
    }

    PCCERT_CONTEXT certFromBinary = CertCreateCertificateContext(X509_ASN_ENCODING, PBYTE(cert.data()), cert.size());
    PCCERT_CONTEXT certInStore = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, certFromBinary, 0);
    CertFreeCertificateContext(certFromBinary);

    if (!certInStore) {
        CertCloseStore(store, 0);
        return {CKR_KEY_NEEDED}; // FIXME: TBS
    }

    DWORD flags = obtainKeyStrategy | CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG;
    DWORD spec = 0;
    BOOL freeKeyHandle = false;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = NULL;
    BOOL gotKey = true;
    // HWND
    gotKey = CryptAcquireCertificatePrivateKey(certInStore, flags, (void *)&parent, &key, &spec, &freeKeyHandle);
    CertFreeCertificateContext(certInStore);
    CertCloseStore(store, 0);

    if (gotKey == FALSE) {
        DWORD e = GetLastError();
        _log("Did not get key: 0x%08x", e);
        if (SCARD_W_CANCELLED_BY_USER == e) {
            return {CKR_FUNCTION_CANCELED};
        } else {
            return {CKR_GENERAL_ERROR};
        }
    }
    // Certificate not needed any more, key handle acquired
    switch (spec)
    {
    case CERT_NCRYPT_KEY_SPEC:
    {
        // https://docs.microsoft.com/en-us/archive/blogs/alejacma/smart-cards-pin-gets-cached
        NCryptSetProperty(key, NCRYPT_PIN_PROPERTY, nullptr, 0, 0);

        err = NCryptSignHash(key, &padInfo, PBYTE(hash.data()), DWORD(hash.size()), PBYTE(result.data()), DWORD(result.size()), (DWORD*)&size, BCRYPT_PAD_PKCS1);
        if (freeKeyHandle) {
            NCryptFreeObject(key);
        }
        result.resize(size);
        break;
    }
    case AT_SIGNATURE:
    {
        // https://docs.microsoft.com/en-us/archive/blogs/alejacma/smart-cards-pin-gets-cached
        CryptSetProvParam(key, PP_SIGNATURE_PIN, nullptr, 0);

        HCRYPTHASH capihash = 0;
        if (!CryptCreateHash(key, alg, 0, 0, &capihash)) {
            if (freeKeyHandle) {
                CryptReleaseContext(key, 0);
            }
            _log("CreateHash failed");
            return {CKR_GENERAL_ERROR};
        }

        if (!CryptSetHashParam(capihash, HP_HASHVAL, PBYTE(hash.data()), 0))	{
            if (freeKeyHandle) {
                CryptReleaseContext(key, 0);
            }
            CryptDestroyHash(capihash);
            _log("CryptSetHashParam failed");
            return {CKR_GENERAL_ERROR};
        }

        INT retCode = CryptSignHashW(capihash, AT_SIGNATURE, 0, 0, PBYTE(result.data()), &size);
        err = retCode ? ERROR_SUCCESS : GetLastError();
        _log("CryptSignHash() return code: %u (%s) %x", retCode, retCode ? "SUCCESS" : "FAILURE", err);
        if (freeKeyHandle) {
            CryptReleaseContext(key, 0);
        }
        CryptDestroyHash(capihash);
        // TODO: link to docs
        result.resize(size);
        std::reverse(result.begin(), result.end());
        break;
    }
    default:
        _log("Invalid key type (not CERT_NCRYPT_KEY_SPEC nor AT_SIGNATURE)");
        return {CKR_GENERAL_ERROR};
    }

    switch (err)
    {
    case ERROR_SUCCESS:
        rv = CKR_OK;
        break;
    case SCARD_W_CANCELLED_BY_USER:
    case ERROR_CANCELLED:
        rv = CKR_FUNCTION_CANCELED;
        break;
    case SCARD_W_CHV_BLOCKED:
        rv = CKR_PIN_LOCKED;
        break;
    case NTE_INVALID_HANDLE: // TODO: document
        _log("NTE_INVALID_HANDLE");
        rv = CKR_GENERAL_ERROR;
        break;
    default:
        _log("Signing failed: 0x%u08x", err);
        rv = CKR_GENERAL_ERROR;
    }
    return {rv, {result}};
}

#endif