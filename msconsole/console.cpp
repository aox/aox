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

    QLabel * label = new QLabel( tr( "&Categories" ), w );
    d->paneList = new QListView( w);
    label->setBuddy( d->paneList );

    QBoxLayout * l = new QBoxLayout( w, QBoxLayout::TopToBottom, 6 );
    l->addWidget( label );
    l->addWidget( d->paneList );
    l->addWidget( new SearchEdit( tr( "(Search)" ), w ) );

    d->stack = new QWidgetStack( this );

    setResizeMode( w, KeepSize );
    setResizeMode( d->stack, Stretch );
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

#if 0
    w = new UserPane( this );
    d->stack->addWidget( w, i );
    i = new QListViewItem( d->paneList, tr( "&Users" ) );
    d->panes->insert( i, w );
    d->items->insert( w, i );
#endif

    d->paneList->setSelected( i, true ); // select a pane to start with
    d->paneList->setCurrentItem( i );

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
