/*
 * Copyright (C) 2017 Martin Paljak
 */

#pragma once

#include "qpki.h"

#include "debuglog.h"
#include "webeid.h"
#include "util.h"

#include "dialogs/betterdialog.h"

#include <QVBoxLayout>

#include <QStandardItemModel>
#include <QComboBox>

#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>


class QtSelectCertificate: public BetterDialog {
    Q_OBJECT

public:

    QtSelectCertificate(const WebContext *ctx, const CertificatePurpose certtype):
        type(certtype),
        layout(new QVBoxLayout(this)),
        message(new QLabel(this)),
        select(new QComboBox(this)),
        buttons(new QDialogButtonBox(this))
    {
        layout->addWidget(message);
        layout->addWidget(select);
        layout->addWidget(buttons);

        layout->setSizeConstraint(QLayout::SetFixedSize);
        select->setFocusPolicy(Qt::StrongFocus);

        setWindowFlags(Qt::WindowStaysOnTopHint);
        // remove minimize and maximize buttons
        setWindowFlags((windowFlags()|Qt::CustomizeWindowHint) &
                       ~(Qt::WindowMaximizeButtonHint|Qt::WindowMinimizeButtonHint|Qt::WindowCloseButtonHint));

        setAttribute(Qt::WA_DeleteOnClose);

        setWindowTitle(ctx->friendlyOrigin());
        message->setText(tr("Selected certificate will be forwarded to the remote website"));

        ok = buttons->addButton(tr("Select"), QDialogButtonBox::AcceptRole);
        ok->setEnabled(false);
        ok->setFocusPolicy(Qt::StrongFocus);

        cancel = buttons->addButton(tr("Cancel"), QDialogButtonBox::RejectRole);
        cancel->setFocusPolicy(Qt::StrongFocus);

        connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

        connect(this, &QDialog::accepted, [this, ctx] {
            // Find the certificate with the matching name
            for (const auto &c: certs) {
                if (certName(c) == select->currentText()) {
                    return emit certificateSelected(c);
                }
            }
        });

        connect(select, static_cast<void(QComboBox::*)(const QString &)>(&QComboBox::currentIndexChanged), this, [=](const QString &text) {
            if (!text.isEmpty()) {
                _log("Item changed to %s", qPrintable(text));
            }
            //    ok->setEnabled(true);
            //    ok->setDefault(true);
            //    ok->setFocus();
        });
        centrify(true, true);
    }

public slots:
    // Called from PKI after QtPKI::refresh() when a card has been inserted and certificate list changes.
    void update(const QVector<QByteArray> &newcerts) {
        QVector<QByteArray> certs;
        // Filter by usage.
        for (const auto &c: newcerts) {
            if (QPKI::usageMatches(c, type)) {
                certs.append(c);
            }
        }
        this->certs = certs;
        // Change from some to none, interpret as implicit cancel
        // TODO: what about changing cards?
        select->clear();
        select->setVisible(certs.size() > 1);
        if (certs.empty()) {
            message->setText(tr("No certificates found, please insert your card!"));
            ok->hide();
            cancel->setDefault(true);
            cancel->setFocus();
        } else if (certs.size() == 1) {
            ok->setText(tr("OK"));

            QSslCertificate x509(certs.at(0), QSsl::Der);
            QString cname = certName(certs.at(0));
            select->addItems({cname});
            if (QDateTime::currentDateTime() >= x509.expiryDate()) {
                ok->setEnabled(false);
                cancel->setDefault(true);
                cancel->setFocus();
                message->setText(tr("Certificate for %1 has expired").arg(cname));
            } else {
                ok->show();
                ok->setEnabled(true);
                ok->setDefault(true);
                ok->setFocus();
                message->setText(tr("Use %1 for %2?").arg(cname).arg(type == Authentication ? tr("authentication") : tr("signing")));
            }
        } else {
            message->setText(type == Authentication ? tr("Select certificate for authentication") : tr("Select certificate for signing"));

            for (const auto &c: certs) {
                select->addItem(certName(c));
            }

            // Disable expired certs
            QStandardItemModel* model = qobject_cast<QStandardItemModel*>(select->model());
            for (const auto &c: certs) {
                QSslCertificate x509(c, QSsl::Der);
                QString cname = certName(c);
                QStandardItem *item = model->findItems(cname).at(0);

                if (QDateTime::currentDateTime() >= x509.expiryDate()) {
                    item->setEnabled(false);
                    item->setToolTip(tr("Certificate has expired"));
                } else {
                    select->setCurrentText(cname);
                }
            }


            ok->show();
            ok->setDefault(true);
            if (select->currentIndex() != -1) {
                ok->setEnabled(true);
                ok->setDefault(true);
                ok->setFocus();
                cancel->setDefault(false);
            }

            ok->setFocus();
        }
        centrify();
        show();
        activateWindow();
        raise();
    }

    void cardInserted(const QString &reader, const QByteArray &atr, const QStringList &flags) {
        (void)atr;
        if (flags.contains("MUTE")) {
            message->setText(tr("Inserted card is not usable. Please check.").arg(reader));
        } else {
            message->setText(tr("Card inserted, looking for certificates ..."));
            // If we currently have only one certificate, re-show the select box.
            if (certs.size() == 1) {
                select->clear();
                select->addItems({certName(certs.at(0))});
                select->show();
            }
        }
        centrify();
    }

    void noDriver(const QString &reader, const QByteArray &atr, const QByteArray &extra) {
        _log("No driver for card in %s (%s) %s", qPrintable(reader), qPrintable(atr.toHex()), qPrintable(extra.toHex()));
        message->setText(tr("No driver available. <a href=\"http://smartcard-atr.appspot.com/parse?ATR=%1\">More information</a>").arg(QString(atr.toHex())));
        message->setTextFormat(Qt::RichText);
        message->setTextInteractionFlags(Qt::TextBrowserInteraction);
        message->setOpenExternalLinks(true);
        centrify();
        connect(message, &QLabel::linkActivated, this, [this] {
            reject();
        });
    }

    QString certName(const QByteArray &c) {
        QString crt;

        QSslCertificate cert(c, QSsl::Der);
        if (cert.isNull())
        {
            _log("Could not parse certificate");
            return QString();
        }

        if (cert.subjectInfo(QSslCertificate::Organization).size() > 0)
        {
            crt += cert.subjectInfo(QSslCertificate::Organization).at(0) + ": ";
        }
        crt += cert.subjectInfo(QSslCertificate::CommonName).at(0) + " ";
        return crt;
    }

signals:
    void certificateSelected(const QByteArray &cert);

private:
    CertificatePurpose type;
    QVector<QByteArray> certs;
    QVBoxLayout *layout;
    QLabel *message;
    QComboBox *select;
    QDialogButtonBox *buttons;
    QPushButton *ok;
    QPushButton *cancel;
};

