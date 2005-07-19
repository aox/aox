// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "logpane.h"

#include "guilog.h"

#include <qlayout.h>
#include <qlistview.h>


/*! \class LogPane logpane.h

    The LogPane class shows the log events for the console itself.

    In the future, it probably should be extended to parse, filter and
    display a log file as well. Or at least show log data for the
    running servers.
*/

LogPane::LogPane( QWidget * parent )
    : QWidget( parent )
{
    QListView * v = new QListView( this );
    GuiLog::setListView( v );

    v->addColumn( tr( "Transaction" ) );
    v->addColumn( tr( "Time" ) );
    v->addColumn( tr( "Facility" ) );
    v->addColumn( tr( "Severity" ) );
    v->addColumn( tr( "Message" ) );

    v->setAllColumnsShowFocus( true );
    v->setSorting( 1 );

    QVBoxLayout * tll = new QVBoxLayout( this );
    tll->addWidget( v );
}


LogPane::~LogPane()
{
    // nothing necessary, but the destructor must exist
}
