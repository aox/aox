// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILBOXPANE_H
#define MAILBOXPANE_H

#include <qwidget.h>


class MailboxPane: public QWidget
{
    Q_OBJECT
public:
    MailboxPane( QWidget * );

private slots:

private:
    class MailboxPaneData * d;
};


#endif
