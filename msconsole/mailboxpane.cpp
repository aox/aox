// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "mailboxpane.h"
#include "mailbox.h"

#include <qlayout.h>
#include <qlabel.h>
#include <qheader.h>
#include <qpushbutton.h>
#include <qlistview.h>


class MailboxPaneData
{
public:
    MailboxPaneData() 
        : mailboxes( 0 ), shown( false )
    {}

    QListView * mailboxes;
    bool shown;
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
    d->mailboxes->setRootIsDecorated( true );
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


class MailboxItem: public QListViewItem
{
public:
    MailboxItem( Mailbox * mailbox, QListViewItem * parent )
        : QListViewItem( parent ), m( mailbox )
    {
    }
    MailboxItem( Mailbox * mailbox, QListView * parent )
        : QListViewItem( parent ), m( mailbox )
    {
    }
    QString text ( int column ) const
    {
        if ( column > 0 )
            return "";
        return QString::fromUtf8( m->name().cstr() );
    }

private:
    Mailbox * m;
};


/*! Adds all children of \a parent to the mailboxes listview, showing
    them as children of \a item. Recursively calls itself.

    If \a parent is null, this function does nothing. If \a item is
    null, the children are added to the listview as top-level items.
*/

int MailboxPane::addChildren( Mailbox * parent, QListViewItem * item )
{
    if ( !parent )
        return 0;
    List<Mailbox> * children = parent->children();
    if ( !children )
        return 0;
    List<Mailbox>::Iterator i( children->first() );
    uint n = 0;
    while ( i ) {
        MailboxItem * mi = 0;
        if ( item )
            mi = new MailboxItem( i, item );
        else
            mi = new MailboxItem( i, d->mailboxes );
        n++;
        n += addChildren( i, mi );
        ++i;
    }
    if ( item && item->firstChild() )
        item->setOpen( n < 3 );
    return n;
}


void MailboxPane::showEvent( QShowEvent *show )
{
    if ( !d->shown ) {
        (void)addChildren( Mailbox::root(), 0 );
        if ( d->mailboxes->childCount() > 0 )
            d->shown = true;
    }
    QWidget::showEvent( show );
}
