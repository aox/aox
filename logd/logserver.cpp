/*! \class LogServer logserver.h
    The LogServer listens for log items on a TCP socket and commits
    them to file intelligently.

    Each logged item belongs to a transaction (a base-36 number), has a
    level of seriousness (debug, info, error or disaster) and a text. If
    the transaction ID is 0, the item is logged immediately, else it's
    held in memory until the transaction is committed.

    When a log transaction is committed, the client can decide what to
    commit. For example, debugging can be discarded and the rest logged.

    If the client crashes or unexpectedly closes the TCP connection,
    everything belonging to pending transactions is immediately written
    to disk.
*/

#include "logserver.h"

#include "buffer.h"
#include "log.h"
#include "list.h"
#include "arena.h"
#include "scope.h"

#include <stdio.h> // fprintf, stderr. replace this somehow.


static uint id = 0;


class LogServerData
{
public:
    LogServerData(): a( 0 ), w( 0 ), id( ::id++ ) {}

    Arena * a;
    Buffer * w;
    uint id;

    class Line
    {
    public:
        Line( uint t, Log::Severity s, const String & l )
            : tag( t ), severity( s ), line( l ) {}
        uint tag;
        Log::Severity severity;
        String line;
    };

    List<Line> pending;
};


/*! Constructs an empty LogServer, listening on socket \a s. */

LogServer::LogServer( int s )
    : Connection( s ), d( new LogServerData )
{
    d->a = new Arena;
}


/*! \reimp */

void LogServer::react( Event e )
{
    switch ( e ) {
    case Read:
        parse();
        break;
    case Timeout:
        // Timeout never should happen
    case Shutdown:
        log( 0, Log::Debug, "log server shutdown" );
        commit( 0, Log::Debug );
        break;
    case Connect:
    case Error:
    case Close:
        if ( !d->pending.isEmpty() ) {
            log( 0, Log::Error,
                 "log client unexpectedly died. open transactions follow." );
            commit( 0, Log::Debug );
        }
        break;
    };
}


/*! Parses messages from the log client. */

void LogServer::parse()
{
    Scope x( d->a );

    String *s = readBuffer()->removeLine();
    if ( !s )
        return;

    processLine( *s );
}


/*! Processes the single \a line, adding it to the log output as
    appropriate.
*/

void LogServer::processLine( const String & line )
{
    uint i = 0;
    while ( line[i] > ' ' )
        i++;
    bool ok = true;
    if ( line[i] != ' ' )
        ok = false;
    i++;
    uint command = i;
    while ( line[i] > ' ' )
        i++;
    if ( line[i] != ' ' )
        ok = false;
    i++;
    if ( ok && line[i] > ' ' )
        process( line.mid( 0, command-1 ),
                 line.mid( command, i-1-command ),
                 line.mid( i ).simplified() );
}


/*! This private function processes a log line beloging to \a
    transaction, of type \a priority and with \a parameters.
*/

void LogServer::process( String transaction,
                         String priority,
                         String parameters )
{
    bool c = false;
    if ( priority == "commit" ) {
        priority = parameters;
        parameters = "";
        c = true;
    }

    Log::Severity s;
    if ( priority == "debug" )
        s = Log::Debug;
    else if ( priority == "info" )
        s = Log::Info;
    else if ( priority == "error" )
        s = Log::Error;
    else if ( priority == "disaster" )
        s = Log::Disaster;
    else
        return;

    bool ok = true;
    uint tag = transaction.number( &ok, 36 );
    if ( !ok )
        return;

    if ( !c )
        log( tag, s, parameters );
    else if ( tag > 0 )
        commit( tag, s );
}


/*! Commits all log lines of \a severity or higher from transaction \a
    tag to the log file, and discards lines of lower severity.

    If \a tag is 0, everything is logged. Absolutely everything.
*/

void LogServer::commit( uint tag, Log::Severity severity )
{
    List< LogServerData::Line >::Iterator i;

    i = d->pending.first();
    while ( i ) {
        LogServerData::Line *l = i;

        if ( tag == 0 || tag == l->tag ) {
            d->pending.take(i);
            if ( tag == 0 || l->severity >= severity )
                output( l->tag, l->severity, l->line );
        }
        else {
            i++;
        }
    }

    if ( d->w )
        d->w->write( 2 );
    if ( d->pending.isEmpty() ) {
        // we've just flushed the buffer and all pending
        // transactions. time to drop the old arena and free up some
        // memory.
        d->w = 0;
        d->a->clear();
    }
}


/*! Saves \a line under \a tag, \a severity, for later logging by
    commit(). With one exception: If \a tag is 0, \a line is logged
    immediately.
*/

void LogServer::log( uint tag, Log::Severity severity, const String & line )
{
    if ( tag > 0 ) {
        d->pending.append( new LogServerData::Line( tag, severity, line ) );
    }
    else {
        output( tag, severity, line );
        d->w->write( 2 );
    }
}


/*! This private function actually writes to the log file, reopening
    it if necessary. \a tag and \a severity are converted to text
    representations, \a line is logged as-is.
*/

void LogServer::output( uint tag,
                       Log::Severity severity,
                       const String &line )
{
    if ( d->w == 0 )
        d->w = new Buffer;
    d->w->append( Log::severity( severity ) );
    d->w->append( ": " );
    d->w->append( String::fromNumber( d->id, 36 ) );
    d->w->append( "/" );
    d->w->append( String::fromNumber( tag, 36 ) );
    d->w->append( ": " );
    d->w->append( line );
    d->w->append( "\n" );
}
