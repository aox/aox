// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILBOXPANE_H
#define MAILBOXPANE_H

#include <qwidget.h>

class Mailbox;
class QListViewItem;


class MailboxPane: public QWidget
{
    Q_OBJECT
public:
    MailboxPane( QWidget * );
    ~MailboxPane();

    int addChildren( Mailbox *, QListViewItem * );
    void showEvent( QShowEvent * );

private slots:
    void mailboxSelected();

private:
    class MailboxPaneData * d;
};


#endif
