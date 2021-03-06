/*
 * Copyright (C) 2017 Martin Paljak
 */


#pragma once

#include "dialogs/betterdialog.h"
#include <QLabel>
#include <QVBoxLayout>
#include <QDialogButtonBox>

#include "qpcsc.h"

// TODO: merge with "insert card"
class QtReaderInUse: public BetterDialog {
    Q_OBJECT

public:
    QtReaderInUse(const QString &origin, const QString &reader):
        layout(new QVBoxLayout(this)),
        buttons(new QDialogButtonBox(this)),
        message(new QLabel(this))
    {
        layout->addWidget(message);
        layout->addWidget(buttons);
        setWindowFlags(Qt::WindowStaysOnTopHint);
        setAttribute(Qt::WA_DeleteOnClose);

        setWindowTitle(tr("%1 @ %2").arg(reader).arg(origin));
        message->setText(tr("%1 is used by %2.\nPress cancel to end access").arg(reader).arg(origin));

        // remove minimize and maximize buttons
        setWindowFlags((windowFlags()|Qt::CustomizeWindowHint) &
                       ~(Qt::WindowMaximizeButtonHint|Qt::WindowMinimizeButtonHint|Qt::WindowCloseButtonHint));
        buttons->addButton(tr("Cancel"), QDialogButtonBox::RejectRole);
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
        show();
        raise();
        activateWindow();
    };

private:
    QVBoxLayout *layout;
    QDialogButtonBox *buttons;
    QLabel *message;
};
