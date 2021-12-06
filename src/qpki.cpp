/*
 * Copyright (C) 2017 Martin Paljak
 */

#include "qpki.h"

#include "webeid.h"
#include "debuglog.h"
#include "util.h"

#include "oracle.h"
#include "qwincrypt.h"

#include "dialogs/select_cert.h"
#include "dialogs/pin.h"

#include <QtConcurrent>

#include <QSslCertificate>
#include <QSslCertificateExtension>


void QPKIWorker::refreshModule(const QString& module) {
    PKCS11Module* m = nullptr;
    _log("Trying module %s", qPrintable(module));
    if (!modules.contains(module)) {
        _log("Module not yet loaded, doing it");
        m = new PKCS11Module();
        if (m->load(module.toStdString()) == CKR_OK) {
            modules[module] = m;
            m->refresh();
            _log("Module loaded with %d certificates", m->getCerts().size());
            // Use first module that reports certificates
        } else {
            _log("Could not load module %s", qPrintable(module));
            return;
        }
    } else {
        _log("%s is already loaded", qPrintable(module));
        m->refresh();
        _log("Module refreshed with %d certificates", m->getCerts().size());
    }

    // re-get all certificates from this modules
    QMap<QByteArray, P11Token> certs;
    for (auto& c : m->getCerts()) {
        c.second.module = module.toStdString();
        certs[v2ba(c.first)] = c.second;
    }

    // If certificate list changed, emit signal
    // FIXME:always triggers.
    if (certificates.size() != certs.size() || 1) {
        certificates = certs;
        emit refreshed(certificates);
    }
}

void QPKIWorker::login(const QByteArray &cert, const QString &pin) {
    _log("Login in worker");
    PKCS11Module *m = modules[QString::fromStdString(certificates[cert].module)];
    // Block with pinpad
    CK_RV rv = m->login(ba2v(cert), pin.toLatin1().data());
    // Too bad.
    if (rv == CKR_USER_ALREADY_LOGGED_IN)
        rv = CKR_OK;
    emit loginDone(rv);
}

// FIXME: hashtype
void QPKIWorker::sign(const QByteArray &cert, const QByteArray &hash) {
    _log("Signing in worker");
    PKCS11Module *m = modules[QString::fromStdString(certificates[cert].module)];
    // Takes a sec or so
    std::vector<unsigned char> result;
    CK_RV rv = m->sign(ba2v(cert), ba2v(hash), result);
    emit signDone(rv, v2ba(result));
}

/////////// QPKI


void QPKI::handleCardInserted(const QString &reader, const QByteArray &atr) {
    _log("Card inserted to %s (%s), refreshing available certificates", qPrintable(reader), qPrintable(atr.toHex()));
    // Check if module already present
    QStringList mods = CardOracle::atrOracle(atr);

    // Check configuration
    if (mods.size() > 0) {
        for (const auto &m: mods) {
            if (m == "IGNORE") {
                _log("Ignoring this card");
                return;
            } else if (m == "CAPI") {
                _log("Using CryptoAPI for card");
                // Give Windows time to start the drivers
                refreshCAPI();
                return;
            } else {
                _log("Refreshing module in PKI thread");
                // Let the worker do the trick
                return emit refreshModule(m);
            }
        }
    } else {
        _log("No ATR configured, emitting no driver");
        emit noDriver(reader, atr, 0);
    }
}

void QPKI::handleCardRemoved(const QString &reader) {
    _log("Card removed from %s, refreshing certificates", qPrintable(reader));
    // If any of the certificates lists this reader, refresh the specified module
    //refresh(0);
}



void QPKI::updateCertificates(const QMap<QByteArray, P11Token> certs) {
    // FIXME
    certificates = certs;
    _log("Updated certificates, emitting as well. %d", certificates.size());
    return emit certificateListChanged(QVector<QByteArray>::fromList(certificates.keys()));
}

QVector<QByteArray> QPKI::getCertificates() {
    return QVector<QByteArray>::fromList(certificates.keys());
}



void QPKI::refreshCAPI() {
#ifdef Q_OS_WIN
    connect(&wincerts, &QFutureWatcher<QWinCrypt::ErroredResponse>::finished, this, [this] {
        this->wincerts.disconnect(); // remove signals
        QWinCrypt::ErroredResponse result = this->wincerts.result();
        _log("Wincerts done: %s %d", QPKI::errorName(result.error), result.result.size());
        if (result.error == CKR_OK) {
            //
            // Make a set for easy operations
            _log("Refreshed CAPI certs");

            // Add new certificates
            for (auto& c : result.result) {
                if (certificates.contains(c)) {
                    _log("Already present!");
                } else {
                    _log("Parsing certificate");
                    QSslCertificate crt(c, QSsl::Der);
                    QString cn = crt.subjectInfo(QSslCertificate::CommonName).join(' ');
                    _log("Adding certificate %s", qPrintable(cn));
                    certificates[c] = P11Token({0,0,{0},0,0,0, "CAPI"});
                }
            }

            // and remove ones that are gone.
            for (auto & c: certificates.keys()) {
                if (QString::fromStdString(certificates[c].module) == "CAPI" && !result.result.contains(c)) {
                    QSslCertificate crt(c, QSsl::Der);
                    QList<QString> cn = crt.subjectInfo(QSslCertificate::CommonName);
                    _log("Certificate has disappeared: %s", qPrintable(cn.at(0)));
                    certificates.remove(c);
                }
            }
        }
    });
    wincerts.setFuture(QtConcurrent::run(&QWinCrypt::getCertificates));
#endif

}

// Select a single certificate for a web context, signal certificate() when done
void QPKI::select(const WebContext* context, const CertificatePurpose type) {
    _log("Selecting certificate for %s", qPrintable(context->friendlyOrigin()));
    QSettings settings;

    // FIXME: force this if any of certificates is PCKS#11
    if (settings.value("ownDialogs", false).toBool() || QSysInfo::productType() != "windows") {
        QtSelectCertificate* dlg = new QtSelectCertificate(context, type);
        connect(context, &WebContext::disconnected, dlg, &QDialog::reject);
        connect(PCSC, &QtPCSC::cardInserted, dlg, &QtSelectCertificate::cardInserted, Qt::QueuedConnection);
        connect(this, &QPKI::certificateListChanged, dlg, &QtSelectCertificate::update);
        connect(this, &QPKI::noDriver, dlg, &QtSelectCertificate::noDriver);
        connect(dlg, &QDialog::rejected, this, [this, context] { return emit certificate(context, CKR_FUNCTION_CANCELED, 0); });
        connect(dlg, &QtSelectCertificate::certificateSelected, this,  [this, context](const QByteArray& cert) {
            return emit certificate(context, CKR_OK, cert);
        });
        dlg->update(QVector<QByteArray>::fromList(certificates.keys()));
    } else {
#ifdef Q_OS_WIN
        connect(&winop, &QFutureWatcher<QWinCrypt::ErroredResponse>::finished, this, [this, context] {
            this->winop.disconnect();  // remove signals
            this->winopNotice.hide();  // close window
            QWinCrypt::ErroredResponse result = this->winop.result();
            _log("Winop done: %s %d", QPKI::errorName(result.error), result.result.size());
            if (result.error == CKR_OK) {
                return emit certificate(context, result.error, result.result.at(0));  // FIXME: range check
            } else {
                return emit certificate(context, result.error, 0);
            }
        });
        // run future
        winopNotice.display("Select certificate");
        // XXX Give time to dialog to appear and become topmost
        QTimer::singleShot(firstrun ? 1500 : 0, this, [this, type, context] {
            firstrun = false;
            QString msg = tr("Select certificate for %1").arg(type == Signing ? tr("signing") : tr("authentication"));
            winop.setFuture(
                QtConcurrent::run(&QWinCrypt::selectCertificate, type, context->friendlyOrigin(), msg, HWND(winopNotice.winId())));
        });
#endif
    }
}

// Calculate a signature, emit signature() when done
// FIXME: add message to function signature, signature type as enum
void QPKI::sign(const WebContext *context, const QByteArray &cert, const QByteArray &hash, const QString &hashalgo, CertificatePurpose type) {
    _log("Signing on %s %s:%s", qPrintable(context->friendlyOrigin()), qPrintable(hashalgo), qPrintable(hash.toHex()));

    // FIXME: use only if cert indicates CAPI
#ifndef Q_OS_WIN
    QtPINDialog *dlg = new QtPINDialog(context, cert, certificates[cert], CKR_OK, type);
    connect(context, &WebContext::disconnected, dlg, &QDialog::reject);
    connect(dlg, &QDialog::rejected, this, [this, context] {
        return emit signature(context, CKR_FUNCTION_CANCELED, 0);
    });
    connect(dlg, &QtPINDialog::failed, this, [this, context] (CK_RV rv) {
        return emit signature(context, rv, 0);
    });
    // from dialog to worker
    connect(dlg, &QtPINDialog::login, &worker, &QPKIWorker::login, Qt::QueuedConnection);
    connect(&worker, &QPKIWorker::loginDone, dlg, &QtPINDialog::update, Qt::QueuedConnection);
    connect(dlg, &QDialog::accepted, this, [=] {
        _log("PIN dialog OK, signing stuff");
        // PIN has been successfully verified. Issue a C_Sign, subscribing to the result
        connect(this, &QPKI::signDone, this, [this, context] (CK_RV rv, QByteArray result) {
            // Remove lambda
            QObject::disconnect(this, &QPKI::signDone, this, nullptr);
            _log("Sign done, result is %s", QPKI::errorName(rv));
            return emit signature(context, rv, result);
        });
        _log("Emitting p11sign");
        return emit p11sign(cert, hash);
    });
#endif


// and wire up signals to the worker, that does actual signing
// otherwise run it in a future and wire up signals.
#ifdef Q_OS_WIN
    connect(&winop, &QFutureWatcher<QWinCrypt::ErroredResponse>::finished, this, [this, context] {
        this->winop.disconnect(); // remove signals
        winopNotice.hide();
        QWinCrypt::ErroredResponse result = this->winop.result();
        _log("Winop done: %s %d", QPKI::errorName(result.error), result.result.size());
        if (result.error == CKR_OK) {
            return emit signature(context, result.error, result.result.at(0)); // FIXME: range check
        } else {
            return emit signature(context, result.error, 0);
        }
    });
    // run future
    winopNotice.display("Enter PIN");
    winop.setFuture(QtConcurrent::run(&QWinCrypt::sign, cert, hash, QWinCrypt::HashType::SHA256, HWND(winopNotice.winId())));
#endif

}

// FIXME: move to pkcs11module.h
const char *QPKI::errorName(const CK_RV err) {
    return PKCS11Module::errorName(err);
}

// static
QByteArray QPKI::authenticate_dtbs(const QSslCertificate &cert, const QString &origin, const QString &nonce) {
    QByteArray dtbs;
    // Construct the data to be signed
    auto subject = cert.subjectInfo(QSslCertificate::CommonName);
    auto issuer = cert.issuerInfo(QSslCertificate::CommonName);
    if (subject.size() < 1 || issuer.size() < 1) {
        _log("No CN for subject or issuer!");
        return dtbs;
    }
    _log("Constructing JWT for %s", subject.at(0).toStdString().c_str());

    // Header
    QJsonDocument header_map({
        {"alg", "RS256"}, // TODO: ES256 as well
        {"typ", "JWT"},
        // XXX: Qt 5.5 fails with the following, x5c will be null
        {"x5c", QJsonArray({ QString(cert.toDer().toBase64()) })},
    });
    QByteArray header_json = header_map.toJson(QJsonDocument::Compact);
    QByteArray header = header_json.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    _log("JWT header: %s", header_map.toJson().toStdString().c_str());

    // Payload
    QJsonDocument payload_map({
        {"exp", int(QDateTime::currentDateTimeUtc().toTime_t() + 5*60)}, // TODO: TBS, expires in 5 minutes
        {"iat", int(QDateTime::currentDateTimeUtc().toTime_t())},
        {"aud", origin},
        {"iss", issuer.at(0)}, // TODO: TBS
        {"sub", subject.at(0)}, // TODO: TBS
        {"nonce", nonce},
    });

    QByteArray payload_json = payload_map.toJson(QJsonDocument::Compact);
    QByteArray payload = payload_json.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    _log("JWT payload: %s", payload_map.toJson().toStdString().c_str());

    // calculate DTBS (Data To Be Signed)
    dtbs = header + "." + payload;

    return dtbs;
}

// TODO: move this to QtPKI
bool QPKI::usageMatches(const QByteArray &crt, CertificatePurpose type)
{
    QSslCertificate cert(crt, QSsl::Der);
    bool isCa = true;
    bool isSSLClient = false;
    bool isNonRepudiation = false;

    for (const QSslCertificateExtension &ext: cert.extensions()) {
        QVariant v = ext.value();
//      _log("ext: %s", ext.name().toStdString().c_str());
        if (ext.name() == "basicConstraints") {
            QVariantMap m = ext.value().toMap();
            isCa = m.value("ca").toBool();
        } else if (ext.oid() == "2.5.29.37") {
            // 2.5.29.37 - extendedKeyUsage
            // XXX: these are not declared stable by Qt.
            // Linux returns parsed map (OpenSSL?) OSX 5.8 returns QByteArrays, 5.5 works
            if (v.canConvert<QByteArray>()) {
                // XXX: this is 06082b06010505070302 what is 1.3.6.1.5.5.7.3.2 what is "TLS Client"
                if (v.toByteArray().toHex().contains("06082b06010505070302")) {
                    isSSLClient = true;
                }
            } else if (v.canConvert<QList<QVariant>>()) {
                // Linux
                if (v.toList().contains("TLS Web Client Authentication")) {
                    isSSLClient = true;
                }
            }
        } else if (ext.name() == "keyUsage") {
            if (v.canConvert<QList<QVariant>>()) {
                // Linux
                if (v.toList().contains("Non Repudiation")) {
                    isNonRepudiation = true;
                }
            }
            // FIXME: detect NR from byte array
            // Do a ugly trick for esteid only
            QList<QString> ou = cert.subjectInfo(QSslCertificate::OrganizationalUnitName);
            if (!isNonRepudiation && ou.size() > 0 && ou.at(0) == "digital signature") {
                isNonRepudiation = true;
            }
            _log("keyusage: %s", v.toByteArray().toHex().toStdString().c_str());
        }
    }
    _log("Certificate flags: ca=%d auth=%d nonrepu=%d", isCa, isSSLClient, isNonRepudiation);
    return !isCa &&
           ((type & Authentication && isSSLClient) || (type & Signing && isNonRepudiation));
}