// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "guilog.h"

#include "date.h"

#include <qlistview.h>

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


class LogItem
    : public QListViewItem
{
public:
    LogItem( QListView * parent,
             const String & id, Log::Facility f, Log::Severity s,
             const String & m );

    QString text( int ) const;

    QString key( int, bool ) const;

    QString transaction;
    Log::Facility facility;
    Log::Severity severity;
    QString message;
    uint time;
    uint number;
};

static uint uniq;


LogItem::LogItem( QListView * parent,
                  const String & id, Log::Facility f, Log::Severity s,
                  const String & m )
    : QListViewItem( parent ),
      transaction( QString::fromLatin1( id.data(), id.length() ) ),
      facility( f ), severity( s ),
      message( QString::fromLatin1( m.data(), m.length() ) ),
      time( ::time( 0 ) ), number( ++uniq )
{
}


QString LogItem::text( int col ) const
{
    QString r;
    switch( col ) {
    case 0:
        r = transaction;
        break;
    case 1:
        { // a new scope so the Date object doesn't cross a label
            Date date;
            date.setUnixTime( time );
            r = QString::fromLatin1( date.isoTime().cstr() );
        }
        break;
    case 2:
        r = QString::fromLatin1( Log::facility( facility ) );
        break;
    case 3:
        r = QString::fromLatin1( Log::severity( severity ) );
        break;
    case 4:
        r = message;
        break;
    default:
        break;
    }
    return r;
}

QString LogItem::key( int col, bool ) const
{
    QString r;
    switch( col ) {
    case 0:
        r = transaction;
        break;
    case 1:
        r.sprintf( "%08x %08x", time, number );
        break;
    case 2:
        r[0] = '0' + (uint)facility;
        break;
    case 3:
        r[0] = '0' + (uint)severity;
        break;
    case 4:
        r = message;
        break;
    default:
        break;
    }
    return r;
}


static QListView * listView;


void GuiLog::send( const String & id,
                   Log::Facility f, Log::Severity s,
                   const String & m )
{
    if ( ::listView )
        new LogItem( ::listView, id, f, s, m );
}


void GuiLog::commit( const String &, Log::Severity )
{
}


/*! Records that GuiLog should store all its log messages in \a
    view. The initial value is 0, which means that log messages are
    discarded.

    Calling setListView does not move older log lines into \a view.
*/

void GuiLog::setListView( QListView * view )
{
    ::listView = view;
}


/*! Returns the a pointer to the list view currently used for
    output. The initial value is 0, meaning that output is discarded.
*/

QListView * GuiLog::listView()
{
    return ::listView;
}
