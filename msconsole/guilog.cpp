// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "guilog.h"

#include "allocator.h"
#include "logpane.h"
#include "date.h"

#include <qwidgetstack.h>

// time()
#include <time.h>


/*! \class GuiLog guilog.h

    The GuiLog class redirects log lines to a suitable widget - which
    is generally not shown. Because of this, msconsole doesn't need to
    connect to the logd.
*/

GuiLog::GuiLog()
    : Logger()
{
    // nothing
}

static uint uniq;



class LogMessage
{
public:
    LogMessage( const String & id, Log::Facility f, Log::Severity s,
                const String & m )
        : transaction( id ),
          facility( f ),
          severity( s ),
          message( m ),
          time( ::time( 0 ) ),
          number( ++uniq )
        {}

    String transaction;
    Log::Facility facility;
    Log::Severity severity;
    String message;
    uint time;
    uint number;
};


class LogItem
    : public QListViewItem
{
public:
    LogItem( QListView * parent );
    QString text( int ) const;
    QString key( int, bool ) const;

    uint number;
};


LogItem::LogItem( QListView * parent )
    : QListViewItem( parent ),
      number( parent->childCount()-1 )
{
}


static LogMessage ** recentMessages;
static uint messageBase;


QString LogItem::text( int col ) const
{
    LogMessage * m = recentMessages[number];
    if ( !m )
        return "";
    QString r;
    switch( col ) {
    case 0:
        r = QString::fromLatin1( m->transaction.data(), m->transaction.length() );
        break;
    case 1:
        { // a new scope so the Date object doesn't cross a label
            Date date;
            date.setUnixTime( m->time );
            r = QString::fromLatin1( date.isoTime().cstr() );
        }
        break;
    case 2:
        r = QString::fromLatin1( Log::facility( m->facility ) );
        break;
    case 3:
        r = QString::fromLatin1( Log::severity( m->severity ) );
        break;
    case 4:
        r = QString::fromLatin1( m->message.data(), m->message.length() );
        break;
    default:
        break;
    }
    return r;
}

QString LogItem::key( int col, bool ) const
{
    LogMessage * m = recentMessages[number];
    if ( !m )
        return "";
    QString r;
    switch( col ) {
    case 0:
    case 4:
        r = text( col );
        break;
    case 1:
        r.sprintf( "%08x %08x", m->time, m->number );
        break;
    case 2:
        r[0] = '0' + (uint)m->facility;
        break;
    case 3:
        r[0] = '0' + (uint)m->severity;
        break;
    default:
        break;
    }
    return r;
}


static LogPane * logPane;


void GuiLog::send( const String & id,
                   Log::Facility f, Log::Severity s,
                   const String & m )
{
    if ( !::logPane )
        return;

    if ( !::recentMessages )
        ::recentMessages = (LogMessage**)Allocator::alloc( 128 * sizeof( LogMessage* ) );
    
    ::recentMessages[::messageBase] = new LogMessage( id, f, s, m );
    ::messageBase = (::messageBase + 1) % 128;
    if ( (uint)::logPane->listView()->childCount() < 128 )
        (void)new LogItem( ::logPane->listView() );
    if ( ::logPane->listView()->isVisible() )
        ::logPane->listView()->update();
    if ( ( s == Log::Disaster || s == Log::Error ) &&
         ::logPane->parent() && ::logPane->parent()->inherits( "QWidgetStack" ) )
        ((QWidgetStack*)::logPane->parent())->raiseWidget( ::logPane );
}


void GuiLog::commit( const String &, Log::Severity )
{
}


/*! Records that GuiLog should store all its log messages using \a
    view. The initial value is 0, which means that log messages are
    discarded.

    Calling setLogPane does not move older log lines into \a view.
*/

void GuiLog::setLogPane( LogPane * view )
{
    ::logPane = view;
}


/*! Returns the a pointer to the list view currently used for
    output. The initial value is 0, meaning that output is discarded.
*/

LogPane * GuiLog::logPane()
{
    return ::logPane;
}
