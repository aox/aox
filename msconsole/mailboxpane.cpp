// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "mailboxpane.h"

#include <qlayout.h>
#include <qlabel.h>
#include <qheader.h>
#include <qlistview.h>
#include <qlineedit.h>
#include <qpushbutton.h>
#include <qapplication.h>

#include <sys/types.h> // getpwent, endpwent
#include <pwd.h> // ditto


class MailboxPaneData
{
public:
    MailboxPaneData()
    {}

    QListView * mailboxes;
};


/*! \class MailboxPane mailboxpane.h

    The MailboxPane class shows the mailbox management functions in the
    Console.
*/


/*!  Constructs a MailboxPane. */

MailboxPane::MailboxPane( QWidget * parent )
    : QWidget( parent, "mailbox pane" ), d( new MailboxPaneData )
{
    QGridLayout * tll = new QGridLayout( this, 3, 4, 6 );

    QLabel * l = new QLabel( tr( "&Mailboxes" ), this );
    tll->addWidget( l, 0, 0 );

    d->mailboxes = new QListView( this, "mailbox list" );
    d->mailboxes->addColumn( " " );
    d->mailboxes->header()->hide();
    tll->addWidget( d->mailboxes, 1, 0 );
    l->setBuddy( d->mailboxes );

    QPushButton * pb = new QPushButton( tr( "&Refresh",
                                            "Refresh list all mailboxes" ),
                                        this, "refresh mailbox list" );
    tll->addWidget( pb, 2, 0, AlignLeft ); // writing...
    pb->setFocusPolicy( NoFocus );

    // finally, tell the master grid where it can stretch, and where
    // it must have space.
    tll->setColSpacing( 1, 0 );
    //tll->setColSpacing( 1, QApplication::globalStrut() );
    tll->setColSpacing( 3, 100 );
    /* tll->setColSpacing( 2, strut() ); */
    /* tll->setRowStretch( 9, 2 ); */
    /* tll->setColStretch( 3, 2 ); */
}
