// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "logserver.h"

#include "arena.h"
#include "scope.h"
#include "buffer.h"
#include "list.h"
#include "file.h"
#include "loop.h"
#include "log.h"

// fprintf, stderr
#include <stdio.h>


static uint id = 0;
File *logFile;


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
    LogServerData(): a( 0 ), id( ::id++ ) {}

    Arena * a;
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
    Loop::addConnection( this );
}


/*! Constructs a LogServer which listens nowhere. This can effectively
    only be used by SelfLogger.
*/

LogServer::LogServer()
    : Connection(), d( new LogServerData )
{
    d->a = new Arena;
}


LogServer::~LogServer()
{
    Loop::removeConnection( this );
}


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

    String *s;
    while ( ( s = readBuffer()->removeLine() ) != 0 )
        processLine( *s );
}


/*! Adds a single \a line to the log output.

    The line must consist of a client identifier (numbers and slashes)
    followed by a space, the message facility, a slash and a severity,
    followed by a space and the log message.
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

    if ( c || s > Log::Error ) {
        if ( s > Log::Error )
            s = Log::Debug;
        commit( transaction, f, s );
    }
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

    if ( d->pending.isEmpty() ) {
        // we've just flushed the buffer and all pending transactions.
        // time to drop the old arena and free up some memory.
        d->a->clear();
    }
}


/*! Saves \a line with tag \a t, facility \a f, and severity \a s in the
    list of pending output lines. If \a f is Immediate, however, \a line
    is logged immediately.
*/

void LogServer::log( String t, Log::Facility f, Log::Severity s,
                     const String &line )
{
    if ( f == Log::Immediate )
        output( t, f, s, line );
    else
        d->pending.append( new LogServerData::Line( t, f, s, line ) );
}


/*! This private function actually writes \a line to the log file with
    the \a tag, facility \a f, and severity \a s converted into their
    textual representations.
*/

void LogServer::output( String tag, Log::Facility f, Log::Severity s,
                        const String &line )
{
    String msg;

    msg.append( Log::facility( f ) + "/" + Log::severity( s ) );
    msg.append( ": " );
    msg.append( fn( d->id, 36 ) + "/" + tag );
    msg.append( ": " );
    msg.append( line + "\n" );

    if ( logFile )
        logFile->write( msg );
    else
        fprintf( stderr, "%s", msg.cstr() );
}


/*! Tells all LogServer object to write log information to \a name
    from now on.
*/

void LogServer::setLogFile( const String & name )
{
    File * l = new File( name, File::Append );
    if ( l->valid() )
        ::logFile = l;
    /*
    else
        ::log( Log::Error, "Could not open log file " + name );
    */
}
