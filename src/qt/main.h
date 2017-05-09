/*
 * Web eID app, (C) 2017 Web eID team and contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#pragma once

#include "pkcs11module.h"
#include "context.h"

#include "qpcsc.h"
#include "qpki.h"

#include "internal.h"

// Dialogs
#include "dialogs/select_cert.h"

#include <QApplication>
#include <QSystemTrayIcon>
#include <QTranslator>
#include <QFile>
#include <QVariantMap>
#include <QJsonObject>

#include <QtWebSockets/QtWebSockets>
#include <QWebSocketServer>
#include <QLocalServer>

#ifdef _WIN32
#include <qt_windows.h>
#endif

Q_DECLARE_METATYPE(CertificatePurpose)
Q_DECLARE_METATYPE(P11Token)
Q_DECLARE_METATYPE(InternalMessage)

class QtHost: public QApplication
{
    Q_OBJECT

public:
    QtHost(int &argc, char *argv[]);

    // PCSC and PKI subsystems
    QtPCSC PCSC;
    QPKI PKI;

    // both in a separate thread
    QThread *pki_thread;

public slots:
    // connect new clients
    void processConnect();
    void processConnectLocal();

    // From different threads and subsystems, dispatched to contexts
    void receiveIPC(InternalMessage message);

    // From contexts, in same thread, direct connection
    void dispatchIPC(const InternalMessage &message);

signals:
    // Signals are for separate threads
    void toPKI(InternalMessage message);
    void toPCSC(InternalMessage message);

private:
    QSystemTrayIcon tray;

    QWebSocketServer *ws; // IPv4
    QWebSocketServer *ws6; // IPv6
    QLocalServer *ls; // localsocket

    // Active contexts
    QMap<QString, WebContext *> contexts;

    void shutdown(int exitcode);
    QTranslator translator;
    bool once = false;
};
