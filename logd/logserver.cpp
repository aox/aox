#include "logserver.h"

#include "arena.h"
#include "scope.h"
#include "buffer.h"
#include "list.h"
#include "log.h"


static uint id = 0;


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

class LogServerData {
public:
    LogServerData(): a( 0 ), w( 0 ), id( ::id++ ) {}

    Arena * a;
    Buffer * w;
    uint id;

    class Line {
    public:
        Line( String t, Log::Facility f, Log::Severity s, const String &l )
            : tag( t ), facility( f ), severity( s ), line( l )
        {}

        String tag;
        Log::Facility facility;
        Log::Severity severity;
        String line;
    };

    List< Line > pending;
};


/*! Constructs an empty LogServer, listening on socket \a s. */

LogServer::LogServer( int s )
    : Connection( s, Connection::LogServer ), d( new LogServerData )
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
        log( 0, Log::Immediate, Log::Debug, "log server shutdown" );
        commit( 0, Log::Immediate, Log::Debug );
        break;
    case Connect:
    case Error:
    case Close:
        if ( !d->pending.isEmpty() ) {
            log( 0, Log::Immediate, Log::Error,
                 "log client unexpectedly died. open transactions follow." );
            commit( 0, Log::Immediate, Log::Debug );
        }
        break;
    };
}


/*! Parses log messages from the input buffer. */

void LogServer::parse()
{
    Scope x( d->a );

    String *s = readBuffer()->removeLine();
    if ( s )
        processLine( *s );
}


/*! Adds a single \a line to the log output.

    The line must consist of a client identifier followed
    by the message severity, followed by a log message,
    separated by spaces.
*/

void LogServer::processLine( const String &line )
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


/*! This private function processes a log line belonging to \a
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

    int n = priority.find( '/' );
    if ( n < 0 )
        return;

    String facility = priority.mid( 0, n );
    Log::Facility f;
    if ( facility == "immediate" )
        f = Log::Immediate;
    else if ( facility == "configuration" )
        f = Log::Configuration;
    else if ( facility == "database" )
        f = Log::Database;
    else if ( facility == "authentication" )
        f = Log::Authentication;
    else if ( facility == "imap" )
        f = Log::IMAP;
    else if ( facility == "smtp" )
        f = Log::SMTP;
    else
        return;

    String severity = priority.mid( n+1 );
    Log::Severity s;
    if ( severity == "debug" )
        s = Log::Debug;
    else if ( severity == "info" )
        s = Log::Info;
    else if ( severity == "error" )
        s = Log::Error;
    else if ( severity == "disaster" )
        s = Log::Disaster;
    else
        return;

    if ( !c )
        log( transaction, f, s, parameters );
    else
        commit( transaction, f, s );
}


/*! Commits all log lines of \a severity or higher from transaction \a
    tag to the log file, and discards lines of lower severity. It does
    nothing with the \a facility yet.

    If \a tag is 0, everything is logged. Absolutely everything.
*/

void LogServer::commit( String tag,
                        Log::Facility facility, Log::Severity severity )
{
    List< LogServerData::Line >::Iterator i;

    i = d->pending.first();
    while ( i ) {
        LogServerData::Line *l = i;

        if ( tag == l->tag ) {
            d->pending.take(i);
            if ( l->severity >= severity )
                output( l->tag, l->facility, l->severity, l->line );
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


/*! Saves \a line under \a tag, \a facility, and \a severity, for later
    logging by commit(). With one exception: If \a tag is 0, \a line is
    logged immediately.
*/

void LogServer::log( String tag, Log::Facility facility, Log::Severity severity,
                     const String &line )
{
    // d->pending.append( new LogServerData::Line( tag, facility, severity, line ) );
    output( tag, facility, severity, line );
    d->w->write( 2 );
}


/*! This private function actually writes to the log file, reopening
    it if necessary. \a tag, \a facility, and \a severity are converted
    to text representations, \a line is logged as-is.
*/

void LogServer::output( String tag, Log::Facility facility,
                        Log::Severity severity, const String &line )
{
    if ( d->w == 0 )
        d->w = new Buffer;
    d->w->append( Log::facility( facility ) );
    d->w->append( "/" );
    d->w->append( Log::severity( severity ) );
    d->w->append( ": " );
    d->w->append( String::fromNumber( d->id, 36 ) );
    d->w->append( "/" );
    d->w->append( tag );
    d->w->append( ": " );
    d->w->append( line );
    d->w->append( "\n" );
}
