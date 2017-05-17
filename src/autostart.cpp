/*
 * Copyright (C) 2017 Martin Paljak
 */

#include "autostart.h"
#include <QFile>

#ifdef Q_OS_MACOS
#include <ServiceManagement/ServiceManagement.h>
#endif

bool StartAtLoginHelper::isEnabled() {
    bool enabled = false;
#if defined(Q_OS_LINUX)
    // chekc for presence of desktop entry
    if (QFile("/etc/xdg/autostart/web-eid-service.desktop").exists())
        return true;
    // TODO: if the following file exists as well, it means user has overriden the default
    // startup script, eg disabled (X-MATE-Autostart-enabled=false or something similar)
    //if (QFile(QDir::homePath().filePath(".config/autostart/web-eid-service.desktop")))
#elif defined(Q_OS_MACOS)
    if (CFArrayRef jobs = SMCopyAllJobDictionaries(kSMDomainUserLaunchd)) {
        for (CFIndex i = 0, count = CFArrayGetCount(jobs); i < count; ++i) {
            CFDictionaryRef job = CFDictionaryRef(CFArrayGetValueAtIndex(jobs, i));
            if (CFStringCompare(CFStringRef(CFDictionaryGetValue(job, CFSTR("Label"))), CFSTR("com.web-eid.login"), 0) == kCFCompareEqualTo) {
                enabled = CFBooleanGetValue(CFBooleanRef(CFDictionaryGetValue(job, CFSTR("OnDemand"))));
                break;
            }
        }
        CFRelease(jobs);
    }
#elif defined(Q_OS_WIN32)
    // Check registry entry and if it addresses *this* instance of the app
    // QCoreApplication::applicationFilePath()
#else
#error "Unsupported platform"
#endif
    return enabled;
}

bool StartAtLoginHelper::setEnabled(bool enabled) {
#if defined(Q_OS_LINUX)
    // disable: add a file to ~/.config with "disabled" flag.
    // enable: make sure global autostart exists and user file is removed
#elif defined(Q_OS_MACOS)
    if (!SMLoginItemSetEnabled(CFSTR("com.web-eid.login"), enabled)) {
        //_log("Login Item Was Not Successful");
    }
#elif defined(Q_OS_WIN32)
    // Add registry entry. Utilizing  QCoreApplication::applicationFilePath()
#else
#error "Unsupported platform"
#endif


    return true;
}
