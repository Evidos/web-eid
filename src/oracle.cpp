/*
 * Copyright (C) 2017 Martin Paljak
 */

#include "oracle.h"
#include "debuglog.h"
#include "util.h"

#include <sstream>

#include <stdio.h>
#include <stdlib.h>

#include <QSettings>
#include <QFile>

#ifndef _WIN32
#include <unistd.h>
#include <dlfcn.h>
#else
#include <windows.h>
#include <io.h>
#define F_OK 02
#define access _access
#endif


// We have a list of named lists
struct ModuleATR {
    QString name;
    QStringList atrs;
    QStringList paths;
};

static QList<ModuleATR> createMap() {
    // First add specific ATR-s
    QList<ModuleATR> m{
        {   "e-token",
            {"3BD518008131FE7D8073C82110F4"},
            {"/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib"}
        },
        {   "Estonian ID-card",
            {   "3BFE9400FF80B1FA451F034573744549442076657220312E3043",
                "3BDE18FFC080B1FE451F034573744549442076657220312E302B",
                "3B5E11FF4573744549442076657220312E30",
                "3B6E00004573744549442076657220312E30",
                "3BFE1800008031FE454573744549442076657220312E30A8",
                "3BFE1800008031FE45803180664090A4561B168301900086",
                "3BFE1800008031FE45803180664090A4162A0083019000E1",
                "3BFE1800008031FE45803180664090A4162A00830F9000EF",
                "3BF9180000C00A31FE4553462D3443432D303181",
                "3BF81300008131FE454A434F5076323431B7",
                "3BFA1800008031FE45FE654944202F20504B4903"
            },
            {"CAPI", "/Library/EstonianIDCard/lib/esteid-pkcs11.so", "/Library/OpenSC/lib/opensc-pkcs11.so", "opensc-pkcs11.so"}
        },
        {   "Latvian ID-card",
            {   "3BDD18008131FE45904C41545649412D65494490008C",
                "3BDB960080B1FE451F830012428F536549440F900020"
            },
            {"CAPI", "/Library/latvia-eid/lib/eidlv-pkcs11.bundle/Contents/MacOS/eidlv-pkcs11", "eidlv-pkcs11.so"}
        },
        {   "Finnish ID-card",
            {"3B7B940000806212515646696E454944"},
            {"CAPI", "/Library/mPolluxDigiSign/libcryptoki.dylib", "opensc-pkcs11.so"}
        },
        {   "Lithuanian ID-card",
            {   "3BF81300008131FE45536D617274417070F8",
                "3B7D94000080318065B08311C0A983009000"
            },
            {"CAPI", "/System/Library/Security/tokend/CCSuite.tokend/Contents/Frameworks/libccpkip11.dylib", "/usr/lib/ccs/libccpkip11.so"}
        },

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
        // Then add some last resort wildcards
        {"OpenSC fallback", {"*"}, {"/Library/OpenSC/lib/opensc-pkcs11.so", "opensc-pkcs11.so"}},
#endif

#ifdef Q_OS_WIN
        {"CryptoAPI fallback", {"*"}, {"CAPI"}},
#endif
        {"Yubikey ignore", {"3bf81300008131fe15597562696b657934d4"}, {"IGNORE"}},
    };

    // Log
    for (auto &e: m) {
        _log("%s is handled by TODO", qPrintable(e.name));
    }
    return m;
}

bool CardOracle::isUsable(const QString &token) {
    // Ignore a card
    if (token.toUpper() == "IGNORE")
        return true;
    // Windows special key
    if (token.toUpper() == "CAPI") {
#ifdef Q_OS_WIN
        return true;
#else
        return false;
#endif
    }

    // Otherwise check the module
    if (token.contains("/") || token.contains("\\")) {
        QFile module(token);
        if (!module.exists()) {
            _log("ignoring missing PKCS#11 module %s", qPrintable(token));
            return false;
        }
    }

// Try to load it as well. FIXME: this can be a slow procedure
// try to open XXX: wrap in some common header
#ifdef _WIN32
    HINSTANCE handle = LoadLibraryA(token.toStdString().c_str());
#else
    void* handle = dlopen(token.toStdString().c_str(), RTLD_LOCAL | RTLD_NOW);
#endif
    if (!handle) {
        _log("ignoring PKCS#11 module that did not load: %s", qPrintable(token));
        return false;
    }
#ifdef _WIN32
    FreeLibrary(handle);
#else
    dlclose(handle);
#endif
    return true;
}

// Given an ATR, returns a list of PKCS#11 modules to try and/or CAPI to use CryptoAPI
// Non-existing modules are ignored.
QStringList CardOracle::atrOracle(const QByteArray &atr) {
    static const QList<ModuleATR> atrToDriverList = createMap();

    QStringList result;
    QSettings settings;
    settings.beginGroup("ATR");
    QString atrstring = QString(atr.toHex());
    // Iterate all keys
    for (const auto &c: settings.childKeys()) {
        if ((atrstring.contains(c, Qt::CaseInsensitive) || c == "*") && !result.contains("IGNORE")) {
            _log("Matched %s for %s", qPrintable(c), qPrintable(atrstring));
            QString atrvalue = settings.value(c).toString();
            if (isUsable(atrvalue)) {
                result << atrvalue;
            }
        }
    }

    // Consult built-in config
    if (result.empty()) {
        for (const auto &c: atrToDriverList) {
            for (const auto &a: c.atrs) {
                if ((atrstring.contains(a, Qt::CaseInsensitive) || a == "*") && !result.contains("IGNORE")) {
                    _log("Matched builtin %s for %s as %s", qPrintable(a), qPrintable(atrstring), qPrintable(c.name));
                    for (const auto &p: c.paths) {
                        if (isUsable(p)) {
                            result << p;
                        }
                    }
                }
            }
        }
    }
    result.removeDuplicates();

    // Only one option if card is destined for ignore
    if (result.contains("IGNORE"))
        return {"IGNORE"};

    if (result.empty()) {
        _log("No configuration available for ATR %s", qPrintable(atrstring));
    }

    // log
    for (const auto &r: result) {
        _log("Using %s", qPrintable(r));
    }

    return result;
}
