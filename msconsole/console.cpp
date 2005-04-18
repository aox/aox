// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include <limits.h> // Qt pulls it in and it has to be first

#include "cstring.h"

#include "console.h"
#include "userpane.h"
#include "searchedit.h"
#include "mailboxpane.h"

#include <qlabel.h>
#include <qaccel.h>
#include <qheader.h>
#include <qlayout.h>
#include <qptrdict.h>
#include <qsplitter.h>
#include <qlistview.h>
#include <qwidgetstack.h>
#include <qapplication.h>


class ConsoleData
{
public:
    ConsoleData(): paneList( 0 ), stack( 0 ), splitter( 0 ),
                   panes( new QPtrDict<QWidget> ),
                   items( new QPtrDict<QListViewItem> ) {}
    QListView * paneList;
    QWidgetStack * stack;
    QSplitter * splitter;
    QPtrDict<QWidget> * panes;
    QPtrDict<QListViewItem> * items;
};


/*! \class Console console.h

    The Console class models the main administration window; a
    multi-view affair with tabs.

    Maybe there should be Commit and Rollback buttons?
*/


/*! Constructs a mailstore console window. Does not show it. */

Console::Console()
    : QWidget( 0, "mailstore console" ), d( new ConsoleData )
{
    d->splitter = new QSplitter( this );
    QWidget * w = new QWidget( d->splitter );

    QLabel * label = new QLabel( tr( "&Categories" ), w );
    d->paneList = new QListView( w);
    label->setBuddy( d->paneList );

    QBoxLayout * l = new QBoxLayout( w, QBoxLayout::TopToBottom, 6 );
    l->addWidget( label );
    l->addWidget( d->paneList );
    l->addWidget( new SearchEdit( tr( "(Search)" ), w ) );

    d->stack = new QWidgetStack( d->splitter );

    d->splitter->setResizeMode( w, QSplitter::KeepSize );
    d->splitter->setResizeMode( d->stack, QSplitter::Stretch );
    connect( d->paneList, SIGNAL(selectionChanged()),
             this, SLOT(changePane()) );

    d->paneList->addColumn( " " );
    d->paneList->header()->hide();

    connect( d->stack, SIGNAL(aboutToShow(QWidget *)),
             this, SLOT(indicatePane(QWidget *)) );

    QListViewItem * i;

    w = new UserPane( this );
    d->stack->addWidget( w );
    i = new QListViewItem( d->paneList, tr( "User Management" ) );
    d->panes->insert( i, w );
    d->items->insert( w, i );

    // select a pane to start with
    d->paneList->setSelected( i, true );
    d->paneList->setCurrentItem( i );

    w = new MailboxPane( this );
    d->stack->addWidget( w );
    i = new QListViewItem( d->paneList, tr( "Mailboxes" ) );
    d->panes->insert( i, w );
    d->items->insert( w, i );

#if 0
    w = new UserPane( this );
    d->stack->addWidget( w );
    i = new QListViewItem( d->paneList, tr( "Users" ) );
    d->panes->insert( i, w );
    d->items->insert( w, i );
#endif

    QAccel * quit = new QAccel( this, "Quit" );
    quit->insertItem( QKeySequence( CTRL + Key_Q ) );
    connect( quit, SIGNAL( activated( int ) ),
             qApp, SLOT( quit() ) );
}


/*! This reimplementation helps ensure that enter works appropriately
    in all the lineedits etc.
*/

void Console::keyPressEvent( QKeyEvent * ke )
{
    QWidget * f = focusWidget();
    if ( ke && f &&
         ( ke->key() == Key_Enter ||
           ke->key() == Key_Return ) &&
         ( f->inherits( "QLineEdit" ) ||
           f->inherits( "QListView" ) ||
           f->inherits( "QListBox" ) ) ) {
        (void)focusNextPrevChild( true );
        ke->accept();
    }
    else {
        QWidget::keyPressEvent( ke );
    }
    return;
}


/*! Changes to the pane currently indicated by the pane list view. */

void Console::changePane()
{
    QListViewItem * i = d->paneList->selectedItem();
    if ( !i )
        return;
    QWidget * w = d->panes->find( i );
    if ( !i )
        return;
    d->stack->raiseWidget( w );
}


/*! Ensures that the list view shows the item corresponding to \a w. */

void Console::indicatePane( QWidget * w )
{
    QListViewItem * i = 0;
    if ( w )
        i = d->items->find( w );
    if ( i == d->paneList->selectedItem() )
        return;
    if ( i )
        d->paneList->setSelected( i, true );
    else
        d->paneList->setSelected( d->paneList->selectedItem(), false );
}


void Console::resizeEvent( QResizeEvent * e )
{
    QWidget::resizeEvent( e );
    d->splitter->resize( size() );
}
