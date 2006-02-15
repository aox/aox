// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include <limits.h> // Qt pulls it in and it has to be first

#include "cstring.h"

#include "allocator.h"
#include "mailboxpane.h"
#include "permissioneditor.h"
#include "mailbox.h"

#include <qlayout.h>
#include <qlabel.h>
#include <qheader.h>
#include <qpushbutton.h>
#include <qlistview.h>


class MailboxPaneData
    : public Garbage
{
public:
    MailboxPaneData()
        : mailboxes( 0 ), editor( 0 ), shown( false )
    {}

    QListView * mailboxes;
    PermissionEditor * editor;
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
    Allocator::addEternal( d, "mailbox pane gc-able data" );

    QGridLayout * tll = new QGridLayout( this, 3, 4, 6 );

    QLabel * l = new QLabel( tr( "&Mailboxes" ), this );
    tll->addWidget( l, 0, 0, AlignLeft );

    d->mailboxes = new QListView( this, "mailbox list" );
    d->mailboxes->setRootIsDecorated( true );
    d->mailboxes->addColumn( tr( "Name" ) );
    d->mailboxes->addColumn( tr( "Type" ) );
    tll->addWidget( d->mailboxes, 1, 0 );
    l->setBuddy( d->mailboxes );

    QPushButton * pb = new QPushButton( tr( "&Refresh",
                                            "Refresh list all mailboxes" ),
                                        this, "refresh mailbox list" );
    tll->addWidget( pb, 2, 0, AlignLeft ); // writing...
    pb->setFocusPolicy( NoFocus );

    d->editor = new PermissionEditor( this );
    tll->addWidget( d->editor, 1, 1 );

    // finally, tell the master grid where it can stretch, and where
    // it must have space.
    tll->setColSpacing( 1, 0 );
    //tll->setColSpacing( 1, QApplication::globalStrut() );
    tll->setColSpacing( 3, 100 );
    /* tll->setColSpacing( 2, strut() ); */
    /* tll->setRowStretch( 9, 2 ); */
    /* tll->setColStretch( 3, 2 ); */

    connect( d->mailboxes, SIGNAL(currentChanged( QListViewItem * )),
             this, SLOT(mailboxSelected()) );
}


MailboxPane::~MailboxPane()
{
    Allocator::removeEternal( d );
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
        if ( column > 1 )
            return "";
        if ( column == 1 ) {
            switch( m->type() ) {
            case Mailbox::Synthetic:
                return MailboxPane::tr( "Synthetic" );
            case Mailbox::Ordinary:
                return MailboxPane::tr( "Normal" );
            case Mailbox::Deleted:
                return MailboxPane::tr( "Deleted" );
            case Mailbox::View:
                return MailboxPane::tr( "View" );
            };
        }
        return QString::fromUtf8( m->name().cstr() );
    }

    Mailbox * mailbox() const { return m; }

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
    List<Mailbox>::Iterator i( children );
    uint n = 0;
    while ( i ) {
        MailboxItem * mi = 0;
        if ( item )
            mi = new MailboxItem( i, item );
        else
            mi = new MailboxItem( i, d->mailboxes );
        n++;
        uint c = addChildren( i, mi );
        if ( c < 4 ) // same test as below
            n += c;
        if ( !c && i->deleted() )
            delete mi;
        ++i;
    }
    if ( item && item->firstChild() )
        item->setOpen( n < 4 ); // same test as above
    else if ( !item && d->mailboxes->firstChild() )
        d->mailboxes->firstChild()->setOpen( true );

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


/*! This private slot updates the PermissionEditor based on the
    mailbox view.
*/

void MailboxPane::mailboxSelected()
{
    MailboxItem * i = (MailboxItem*)d->mailboxes->currentItem();
    if ( i )
        d->editor->setMailbox( i->mailbox() );
}
