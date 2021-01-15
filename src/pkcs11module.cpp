/*
 * Copyright (C) 2017 Martin Paljak
 */

#include "pkcs11module.h"
#include "debuglog.h"
#include "util.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <stdexcept>
#include <iostream>
#include <map>
#include <set>
#include <vector>

#include <QSslCertificate>
#include <QSslCertificateExtension>
#include <QByteArray>
#include <QJsonDocument>
#include <QMetaType>
#include <QList>

#ifndef _WIN32
#include <dlfcn.h>
#endif

// TODO: update to PKCS#11 v2.30 header
#define CKR_LIBRARY_LOAD_FAILED               0x000001B7

// Wrapper around a single PKCS#11 module
template <typename Func, typename... Args>
CK_RV Call(const char *fun, const char *file, int line, const char *function, Func func, Args... args)
{
    CK_RV rv = func(args...);
    Logger::writeLog(fun, file, line, "%s: %s", function, PKCS11Module::errorName(rv));
    return rv;
}
#define C(API, ...) Call(__FUNCTION__, __FILE__, __LINE__, "C_"#API, fl->C_##API, __VA_ARGS__)

// return the rv is not CKR_OK
#define check_C(API, ...) do { \
    CK_RV _ret = Call(__FUNCTION__, __FILE__, __LINE__, "C_"#API, fl->C_##API, __VA_ARGS__); \
    if (_ret != CKR_OK) { \
       Logger::writeLog(__FUNCTION__, __FILE__, __LINE__, "returning %s", PKCS11Module::errorName(_ret)); \
       return _ret; \
    } \
} while(0)

std::vector<unsigned char> PKCS11Module::attribute(CK_ATTRIBUTE_TYPE type, CK_SESSION_HANDLE sid, CK_OBJECT_HANDLE obj) const
{
    CK_ATTRIBUTE attr = {type, nullptr, 0};
    C(GetAttributeValue, sid, obj, &attr, 1UL);
    std::vector<unsigned char> data(attr.ulValueLen);
    attr.pValue = data.data();
    C(GetAttributeValue, sid, obj, &attr, 1UL);
    return data;
}

std::vector<CK_OBJECT_HANDLE> PKCS11Module::objects(CK_OBJECT_CLASS objectClass, CK_SESSION_HANDLE session, CK_ULONG count) const
{
    return objects({ {CKA_CLASS, &objectClass, sizeof(objectClass)} }, session, count);
}

std::vector<CK_OBJECT_HANDLE> PKCS11Module::objects(const std::vector<CK_ATTRIBUTE> &attr, CK_SESSION_HANDLE session, CK_ULONG count) const
{
    C(FindObjectsInit, session, const_cast<CK_ATTRIBUTE*>(attr.data()), CK_ULONG(attr.size()));
    CK_ULONG objectCount = count;
    std::vector<CK_OBJECT_HANDLE> objects(objectCount);
    C(FindObjects, session, objects.data(), objects.size(), &objectCount);
    C(FindObjectsFinal, session);
    objects.resize(objectCount);
    return objects;
}

std::vector<CK_OBJECT_HANDLE> PKCS11Module::getKey(CK_SESSION_HANDLE session, const std::vector<unsigned char> &id) const {
    _log("Looking for key with id %s length %d", toHex(id).c_str(), id.size());
    CK_OBJECT_CLASS keyclass = CKO_PRIVATE_KEY;
    return objects({
        {CKA_CLASS, &keyclass, CK_ULONG(sizeof(keyclass))},
        {CKA_ID, (void*)id.data(), CK_ULONG(id.size())}
    }, session, 1);
}


CK_RV PKCS11Module::load(const std::string &module) {
    // Clear any present modules
    certs.clear();
    CK_C_GetFunctionList C_GetFunctionList = nullptr;
#ifdef _WIN32
    library = LoadLibraryA(module.c_str());
    if (library)
        C_GetFunctionList = CK_C_GetFunctionList(GetProcAddress(library, "C_GetFunctionList"));
#else
    library = dlopen(module.c_str(), RTLD_LOCAL | RTLD_NOW);
    if (library) {
#ifdef __linux__
        // Get path to library location, if just a name
        if (path.find_first_of("/\\") == std::string::npos) {
            std::vector<char> path(1024);
            if (dlinfo(library,  RTLD_DI_ORIGIN, path.data()) == 0) {
                std::string p(path.begin(), path.end());
                _log("Loaded %s from %s", module.c_str(), p.c_str());
            } else {
                _log("Warning: could not get library load path");
            }
        }
#endif
        C_GetFunctionList = CK_C_GetFunctionList(dlsym(library, "C_GetFunctionList"));
    }
#endif

    if (!C_GetFunctionList) {
        _log("Module does not have C_GetFunctionList");
        return CKR_LIBRARY_LOAD_FAILED; // XXX Not really what we had in mind according to spec spec, but usable.
    }
    Call(__FUNCTION__, __FILE__, __LINE__, "C_GetFunctionList", C_GetFunctionList, &fl);
    CK_RV rv = C(Initialize, nullptr);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        return rv;
    }
    initialized = rv != CKR_CRYPTOKI_ALREADY_INITIALIZED;

    return refresh();
}

// See if tokens have appeared or disappeared
CK_RV PKCS11Module::refresh() {
    // Locate all slots with tokens
    CK_ULONG slotCount = 0;
    check_C(GetSlotList, CK_BBOOL(CK_TRUE), nullptr, &slotCount);
    _log("slotCount = %i", slotCount);
    std::vector<CK_SLOT_ID> slots_with_tokens(slotCount);
    check_C(GetSlotList, CK_BBOOL(CK_TRUE), slots_with_tokens.data(), &slotCount);
    // Remove any certificates that were in tokens that do not exist any more
    std::set<std::vector<unsigned char>> leftovers;
    for (auto &c: certs) {
        auto sid = c.second.first.slot;
        // remove
        if (std::none_of(slots_with_tokens.cbegin(), slots_with_tokens.cend(), [sid](CK_SLOT_ID t){ return t == sid; }))
            leftovers.insert(c.first);
        else
            _log("Still present");
    }
    for (const auto &l: leftovers) {
        certs.erase(l);
    }
    for (auto &slot: slots_with_tokens) {
        // Check the content of the slot
        CK_TOKEN_INFO token;
        CK_SESSION_HANDLE sid = 0;
        _log("Checking slot %u", slot);
        CK_RV rv = C(GetTokenInfo, slot, &token);
        if (rv != CKR_OK) {
            _log("Could not get token info, skipping slot %u", slot);
            continue;
        }
        std::string label = QString::fromUtf8((const char* )token.label, sizeof(token.label)).simplified().toStdString();
        _log("Token: \"%s\"", label.c_str());
        C(OpenSession, slot, CKF_SERIAL_SESSION, nullptr, nullptr, &sid);
        if (rv != CKR_OK) {
            _log("Could not open session, skipping slot %u", slot);
            continue;
        }
        _log("Opened session: %u", sid);
        // CK_OBJECT_CLASS objectClass
        std::vector<CK_OBJECT_HANDLE> objectHandle = objects(CKO_CERTIFICATE, sid, 2);
        // We now have the certificate handles (valid for this session) in objectHandle
        _log("Found %u certificates from slot %u", objectHandle.size(), slot);
        for (CK_OBJECT_HANDLE handle: objectHandle) {
            // Get DER
            std::vector<unsigned char> certCandidate = attribute(CKA_VALUE, sid, handle);
            // Get certificate ID
            std::vector<unsigned char> certid = attribute(CKA_ID, sid, handle);
            _log("Found certificate: %s %s", x509subject(certCandidate).c_str(), toHex(certid).c_str());
            // add to map
            certs[certCandidate] = std::make_pair(P11Token({int(token.ulMinPinLen), int(token.ulMaxPinLen), label, bool(token.flags & CKF_PROTECTED_AUTHENTICATION_PATH), slot, token.flags, {}}), certid);
        }
        // Close session with this slot. We ignore errors here
        C(CloseSession, sid);
    }
    // List all found certs
    _log("found %d certificates", certs.size());
    for(const auto &cpairs : certs) {
        auto location = cpairs.second;
        _log("certificate: %s in slot %d with id %s", x509subject(cpairs.first).c_str(), location.first.slot, toHex(location.second).c_str());
    }
    return CKR_OK;

}

std::map<std::vector <unsigned char>, P11Token> PKCS11Module::getCerts() {
    std::map<std::vector<unsigned char>, P11Token> res;
    for(auto const &crts: certs) {
        _log("returning certificate: %s", x509subject(crts.first).c_str());
        res.insert(std::make_pair(crts.first, crts.second.first));
    }
    return res;
}

CK_RV PKCS11Module::login(const std::vector<unsigned char> &cert, const char *pin) {
    _log("Issuing C_Login");
    auto slot = certs.find(cert)->second; // FIXME: not found

    // Assumes presence of session
    if (!session) {
        const P11Token token = getP11Token(cert);
        _log("Using key from slot %d with ID %s", slot.first.slot, toHex(slot.second).c_str());
        check_C(OpenSession, token.slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session);
    }
    check_C(Login, session, CKU_USER, CK_UTF8CHAR_PTR(pin), pin ? strlen(pin) : 0);

    return CKR_OK;
}



PKCS11Module::~PKCS11Module() {
    if (session)
        C(CloseSession, session);
    if (initialized)
        C(Finalize, nullptr);
    if (!library)
        return;
#ifdef _WIN32
    FreeLibrary(library);
#else
    dlclose(library);
#endif
}

CK_RV PKCS11Module::sign(const std::vector<unsigned char> &cert, const std::vector<unsigned char> &hash, std::vector<unsigned char> &result) {
    auto slot = certs.find(cert)->second; // FIXME: not found

    // Assumes open session to the right token, that is already authenticated.
    // TODO: correct handling of CKA_ALWAYS_AUTHENTICATE and associated login procedures
    std::vector<CK_OBJECT_HANDLE> key = getKey(session, slot.second); // TODO: function signature and return code
    if (key.size() != 1) {
        _log("Can not sign - no key or found multiple matches");
        return CKR_OBJECT_HANDLE_INVALID;
    }

    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ATTRIBUTE attribute = { CKA_KEY_TYPE, &keyType, sizeof(keyType) };
    check_C(GetAttributeValue, session, key[0], &attribute, 1);

    CK_MECHANISM mechanism = {keyType == CKK_ECDSA ? CKM_ECDSA : CKM_RSA_PKCS, nullptr, 0};
    check_C(SignInit, session, &mechanism, key[0]);
    std::vector<unsigned char> hashWithPadding;
    if(keyType == CKK_RSA)
    {
        // FIXME: explicit hash type argument
        switch (hash.size()) {
        case BINARY_SHA224_LENGTH:
            hashWithPadding = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};
            break;
        case BINARY_SHA256_LENGTH:
            hashWithPadding = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
            break;
        case BINARY_SHA384_LENGTH:
            hashWithPadding = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
            break;
        case BINARY_SHA512_LENGTH:
            hashWithPadding = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
            break;
        default:
            _log("incorrect digest length, dropping padding");
        }
    }
    hashWithPadding.insert(hashWithPadding.cend(), hash.cbegin(), hash.cend());
    CK_ULONG signatureLength = 0;

    // Get response size
    check_C(Sign, session, hashWithPadding.data(), hashWithPadding.size(), nullptr, &signatureLength);
    result.resize(signatureLength);
    // Get actual signature
    check_C(Sign, session, hashWithPadding.data(), hashWithPadding.size(), result.data(), &signatureLength);

    _log("Signature: %s", toHex(result).c_str());

    // We require a new login for next signature
    // return code is ignored
    C(CloseSession, session);
    session = CK_INVALID_HANDLE;
    return CKR_OK;
}

std::pair<int, int> PKCS11Module::getPINLengths(const std::vector<unsigned char> &cert) {
    const P11Token token = getP11Token(cert);
    return std::make_pair(token.pin_min, token.pin_max);
}

bool PKCS11Module::isPinpad(const std::vector<unsigned char> &cert) const {
    return getP11Token(cert).has_pinpad;
}

// FIXME: assumes 3 tries for a PIN
int PKCS11Module::getPINRetryCount(const P11Token &p11token) {
    if (p11token.flags & CKF_USER_PIN_LOCKED)
        return 0;
    if (p11token.flags & CKF_USER_PIN_FINAL_TRY)
        return 1;
    if (p11token.flags & CKF_USER_PIN_COUNT_LOW)
        return 2;
    return 3;
}

const P11Token PKCS11Module::getP11Token(const std::vector<unsigned char> &cert) const {
    auto slotinfo = certs.find(cert);
    return slotinfo->second.first;
}

const char *PKCS11Module::errorName(CK_RV err) {
#define CASE(X) case X: return #X
    switch (err) {
        CASE(CKR_OK);
        CASE(CKR_CANCEL);
        CASE(CKR_HOST_MEMORY);
        CASE(CKR_SLOT_ID_INVALID);
        CASE(CKR_GENERAL_ERROR);
        CASE(CKR_FUNCTION_FAILED);
        CASE(CKR_ARGUMENTS_BAD);
        CASE(CKR_NO_EVENT);
        CASE(CKR_NEED_TO_CREATE_THREADS);
        CASE(CKR_CANT_LOCK);
        CASE(CKR_ATTRIBUTE_READ_ONLY);
        CASE(CKR_ATTRIBUTE_SENSITIVE);
        CASE(CKR_ATTRIBUTE_TYPE_INVALID);
        CASE(CKR_ATTRIBUTE_VALUE_INVALID);
        CASE(CKR_DATA_INVALID);
        CASE(CKR_DATA_LEN_RANGE);
        CASE(CKR_DEVICE_ERROR);
        CASE(CKR_DEVICE_MEMORY);
        CASE(CKR_DEVICE_REMOVED);
        CASE(CKR_ENCRYPTED_DATA_INVALID);
        CASE(CKR_ENCRYPTED_DATA_LEN_RANGE);
        CASE(CKR_FUNCTION_CANCELED);
        CASE(CKR_FUNCTION_NOT_PARALLEL);
        CASE(CKR_FUNCTION_NOT_SUPPORTED);
        CASE(CKR_KEY_HANDLE_INVALID);
        CASE(CKR_KEY_SIZE_RANGE);
        CASE(CKR_KEY_TYPE_INCONSISTENT);
        CASE(CKR_KEY_NOT_NEEDED);
        CASE(CKR_KEY_CHANGED);
        CASE(CKR_KEY_NEEDED);
        CASE(CKR_KEY_INDIGESTIBLE);
        CASE(CKR_KEY_FUNCTION_NOT_PERMITTED);
        CASE(CKR_KEY_NOT_WRAPPABLE);
        CASE(CKR_KEY_UNEXTRACTABLE);
        CASE(CKR_MECHANISM_INVALID);
        CASE(CKR_MECHANISM_PARAM_INVALID);
        CASE(CKR_OBJECT_HANDLE_INVALID);
        CASE(CKR_OPERATION_ACTIVE);
        CASE(CKR_OPERATION_NOT_INITIALIZED);
        CASE(CKR_PIN_INCORRECT);
        CASE(CKR_PIN_INVALID);
        CASE(CKR_PIN_LEN_RANGE);
        CASE(CKR_PIN_EXPIRED);
        CASE(CKR_PIN_LOCKED);
        CASE(CKR_SESSION_CLOSED);
        CASE(CKR_SESSION_COUNT);
        CASE(CKR_SESSION_HANDLE_INVALID);
        CASE(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        CASE(CKR_SESSION_READ_ONLY);
        CASE(CKR_SESSION_EXISTS);
        CASE(CKR_SESSION_READ_ONLY_EXISTS);
        CASE(CKR_SESSION_READ_WRITE_SO_EXISTS);
        CASE(CKR_SIGNATURE_INVALID);
        CASE(CKR_SIGNATURE_LEN_RANGE);
        CASE(CKR_TEMPLATE_INCOMPLETE);
        CASE(CKR_TEMPLATE_INCONSISTENT);
        CASE(CKR_TOKEN_NOT_PRESENT);
        CASE(CKR_TOKEN_NOT_RECOGNIZED);
        CASE(CKR_TOKEN_WRITE_PROTECTED);
        CASE(CKR_UNWRAPPING_KEY_HANDLE_INVALID);
        CASE(CKR_UNWRAPPING_KEY_SIZE_RANGE);
        CASE(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
        CASE(CKR_USER_ALREADY_LOGGED_IN);
        CASE(CKR_USER_NOT_LOGGED_IN);
        CASE(CKR_USER_PIN_NOT_INITIALIZED);
        CASE(CKR_USER_TYPE_INVALID);
        CASE(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
        CASE(CKR_USER_TOO_MANY_TYPES);
        CASE(CKR_WRAPPED_KEY_INVALID);
        CASE(CKR_WRAPPED_KEY_LEN_RANGE);
        CASE(CKR_WRAPPING_KEY_HANDLE_INVALID);
        CASE(CKR_WRAPPING_KEY_SIZE_RANGE);
        CASE(CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
        CASE(CKR_RANDOM_SEED_NOT_SUPPORTED);
        CASE(CKR_RANDOM_NO_RNG);
        CASE(CKR_DOMAIN_PARAMS_INVALID);
        CASE(CKR_BUFFER_TOO_SMALL);
        CASE(CKR_SAVED_STATE_INVALID);
        CASE(CKR_INFORMATION_SENSITIVE);
        CASE(CKR_STATE_UNSAVEABLE);
        CASE(CKR_CRYPTOKI_NOT_INITIALIZED);
        CASE(CKR_CRYPTOKI_ALREADY_INITIALIZED);
        CASE(CKR_MUTEX_BAD);
        CASE(CKR_MUTEX_NOT_LOCKED);
        CASE(CKR_VENDOR_DEFINED);
    default:
        return "UNKNOWN";
    }
}
