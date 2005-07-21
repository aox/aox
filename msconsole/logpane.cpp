// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "logpane.h"

#include "guilog.h"
#include "allocator.h"

#include <qlabel.h>
#include <qlayout.h>
#include <qspinbox.h>
#include <qlistview.h>


class LogPaneData
    : public Garbage
{
public:
    LogPaneData(): log( 0 ), maxLines( 0 ) {}

    QListView * log;
    QSpinBox * maxLines;
};


/*! \class LogPane logpane.h

    The LogPane class shows the log events for the console itself.

    In the future, it probably should be extended to parse, filter and
    display a log file as well. Or at least show log data for the
    running servers.
*/

LogPane::LogPane( QWidget * parent )
    : QWidget( parent ), d( new LogPaneData )
{
    Allocator::addEternal( d, "logpane gcable data" );

    QGridLayout * tll = new QGridLayout( this, 2, 3, 6 );

    d->maxLines = new QSpinBox( this );
    d->maxLines->setMaxValue( 10000 );
    d->maxLines->setMinValue( 128 );
    tll->addWidget( d->maxLines, 0, 2 );

    QLabel * l = new QLabel( tr( "&Maximum log size" ), this );
    l->setBuddy( d->maxLines );
    tll->addWidget( l, 0, 1 );

    d->log = new QListView( this );

    d->log->addColumn( tr( "Transaction" ) );
    d->log->addColumn( tr( "Time" ) );
    d->log->addColumn( tr( "Facility" ) );
    d->log->addColumn( tr( "Severity" ) );
    d->log->addColumn( tr( "Message" ) );

    d->log->setAllColumnsShowFocus( true );
    d->log->setSorting( 1 );

    tll->addMultiCellWidget( d->log, 1, 1, 0, 2 );

    tll->setColStretch( 0, 9999 );

    GuiLog::setLogPane( this );
}


LogPane::~LogPane()
{
    Allocator::removeEternal( d );
}


/*! Returns a pointer to the QListView used to store, display and sort
    the log lines.
*/

QListView * LogPane::listView() const
{
    return d->log;
}


/*! Returns the maximum number of lines to be stored and displayed in
    the log pane.
*/

uint LogPane::maxLines() const
{
    return d->maxLines->value();
}
