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


static uint id;
static File *logFile;
static Log::Severity logLevel;

static Log::Facility facility( const String & );
static Log::Severity severity( const String & );

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
        if ( !d->pending.isEmpty() )
            commit( 0, Log::Immediate, Log::Debug );
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
    uint cmd = 0;
    uint msg = 0;

    cmd = line.find( ' ' );
    if ( cmd > 0 )
        msg = line.find( ' ', cmd+1 );
    if ( msg <= cmd+1 )
        return;

    String transaction = line.mid( 0, cmd );
    String priority = line.mid( cmd+1, msg-cmd-1 );
    String parameters = line.mid( msg+1 ).simplified();

    bool c = false;
    if ( priority == "commit" ) {
        priority = parameters;
        parameters = "";
        c = true;
    }

    int n = priority.find( '/' );
    if ( n < 0 )
        return;

    Log::Facility f = facility( priority.mid( 0, n ) );
    Log::Severity s = severity( priority.mid( n+1 ) );

    if ( !c )
        log( transaction, f, s, parameters );
    if ( c || s >= logLevel ) {
        if ( s >= Log::Error )
            s = Log::Debug;
        commit( transaction, f, s );
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


/*! Commits all log lines of \a severity or higher from transaction \a
    tag to the log file, and discards lines of lower severity. It does
    nothing with the \a facility yet.

    If \a tag is 0, everything is logged. Absolutely everything.
*/

void LogServer::commit( String tag,
                        Log::Facility facility, Log::Severity severity )
{
    List< LogServerData::Line >::Iterator i;
    bool first = true;

    i = d->pending.first();
    while ( i ) {
        LogServerData::Line *l = i;

        if ( tag.isEmpty() ) {
            if ( first )
                log( 0, Log::Immediate, Log::Error,
                     "Log client unexpectedly died. "
                     "All messages in unfinished transactions follow." );
            first = false;
            d->pending.take( i );
            output( l->tag, l->facility, l->severity, l->line );
        }
        else if ( tag == l->tag ) {
            d->pending.take( i );
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
        logFile = l;
    else
        ::log( "Could not open log file " + name, Log::Disaster );
}


/*! Sets the log level to the Severity corresponding to \a l. */

void LogServer::setLogLevel( const String &l )
{
    logLevel = severity( l );
}


static Log::Facility facility( const String &l )
{
    Log::Facility f = Log::General;

    String p = l.lower();
    if ( p == "immediate" )
        f = Log::Immediate;
    else if ( p == "configuration" )
        f = Log::Configuration;
    else if ( p == "database" )
        f = Log::Database;
    else if ( p == "authentication" )
        f = Log::Authentication;
    else if ( p == "imap" )
        f = Log::IMAP;
    else if ( p == "smtp" )
        f = Log::SMTP;
    else if ( p == "server" )
        f = Log::Server;
    return f;
}

static Log::Severity severity( const String &l )
{
    Log::Severity s = Log::Info;

    String p = l.lower();
    if ( p == "debug" )
        s = Log::Debug;
    else if ( p == "info" )
        s = Log::Info;
    else if ( p == "error" )
        s = Log::Error;
    else if ( p == "disaster" )
        s = Log::Disaster;
    return s;
}


/*! Logs a final line in the logfile and reopens it. */

void LogServer::reopen( int )
{
    if ( !logFile )
        return;

    File * l = new File( logFile->name(), File::Append );
    if ( !l->valid() ) {
        ::log( "SIGHUP handler was unable to open new log file" +
               l->name(),
               Log::Disaster );
        ::commit();
        Loop::shutdown(); // XXX: perhaps better to switch to syslog
    }
    ::log( "SIGHUP caught. Closing and reopening log file " + logFile->name(),
           Log::Info );
    ::commit();
    delete logFile;
    logFile = l;
    ::log( "SIGHUP caught. Reopened log file " + logFile->name(),
           Log::Info );
    ::commit();
}
