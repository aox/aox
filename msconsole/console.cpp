#include "cstring.h"

#include "console.h"
#include "userpane.h"

#include <qtabbar.h>
#include <qwidgetstack.h>
#include <qlayout.h>


class ConsoleData
{
public:
    ConsoleData(): tabs( 0 ), stack( 0 ) {}
    QTabBar * tabs;
    QWidgetStack * stack;
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
    d->tabs = new QTabBar( this );
    d->stack = new QWidgetStack( this );
    connect( d->tabs, SIGNAL(selected(int)),
             d->stack, SLOT(raiseWidget(int)) );

    QBoxLayout * tll = new QBoxLayout( this, QBoxLayout::TopToBottom, 0, 0 );
    tll->addWidget( d->tabs );
    tll->addWidget( d->stack, 2 );

    int i = d->tabs->addTab( new QTab( tr( "&Users" ) ) );
    QWidget * w = new UserPane( d->stack );
    d->stack->addWidget( w, i );

    //i = d->tabs->addTab( new QTab( tr( "&Config" ) ) );
    //w = new ConfigPane( d->stack );
    //d->stack->addWidget( w, i );
}

