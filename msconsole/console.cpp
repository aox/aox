// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "console.h"
#include "userpane.h"
#include "searchedit.h"

#include <qlistview.h>
#include <qheader.h>
#include <qwidgetstack.h>
#include <qptrdict.h>
#include <qlayout.h>
#include <qlabel.h>
#include <qaccel.h>
#include <qapplication.h>


class ConsoleData
{
public:
    ConsoleData(): paneList( 0 ), stack( 0 ),
                   panes( new QPtrDict<QWidget> ),
                   items( new QPtrDict<QListViewItem> ) {}
    QListView * paneList;
    QWidgetStack * stack;
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
    : QSplitter( 0, "mailstore console" ), d( new ConsoleData )
{
    QWidget * w = new QWidget( this );
    d->paneList = new QListView( w);
    QBoxLayout * l = new QBoxLayout( w, QBoxLayout::TopToBottom, 6 );
    l->addWidget( new QLabel( tr( "Categories" ), w ) );
    l->addWidget( d->paneList );
    l->addWidget( new SearchEdit( tr( "(Search)" ), w ) );

    QAccel * quit = new QAccel( this, "Quit" );
    quit->insertItem( QKeySequence( CTRL + Key_Q ) );
    connect( quit, SIGNAL( activated( int ) ),
             qApp, SLOT( quit() ) );

    d->stack = new QWidgetStack( this );

    setResizeMode( w, KeepSize );
    setResizeMode( d->stack, Stretch );
    connect( d->paneList, SIGNAL(selectionChanged()),
             this, SLOT(changePane()) );

    d->paneList->addColumn( " " );
    d->paneList->header()->hide();

    QListViewItem * i;

    w = new UserPane( this );
    d->stack->addWidget( w );
    i = new QListViewItem( d->paneList, tr( "User Management" ) );
    d->panes->insert( i, w );
    d->items->insert( w, i );

#if 0
    w = new UserPane( this );
    d->stack->addWidget( w, i );
    i = new QListViewItem( d->paneList, tr( "&Users" ) );
    d->panes->insert( i, w );
    d->items->insert( w, i );
#endif
}
