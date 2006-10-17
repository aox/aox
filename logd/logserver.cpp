// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "logserver.h"

#include "allocator.h"
#include "buffer.h"
#include "dict.h"
#include "list.h"
#include "file.h"
#include "eventloop.h"
#include "log.h"

// fprintf, stderr
#include <stdio.h>
// dup
#include <unistd.h>


static uint id;
static File *logFile;
static Log::Severity logLevel;


/*! \class LogServer logserver.h
    The LogServer listens for log items on a TCP socket and commits
    them to file.

    Each logged item belongs to a transaction (a base-36 number), has a
    level of seriousness (debug, info, error or disaster) and a text.
*/

class LogServerData
    : public Garbage
{
public:
    LogServerData(): id( ::id++ ), name( "(Anonymous)" ) {}

    uint id;

    String name;
};


/*! Constructs an empty LogServer, listening on socket \a s. */

LogServer::LogServer( int s )
    : Connection( s, Connection::LogServer ), d( new LogServerData )
{
    EventLoop::global()->addConnection( this );
}


/*! Constructs a LogServer which listens nowhere. This can effectively
    only be used by SelfLogger.
*/

LogServer::LogServer()
    : Connection(), d( new LogServerData )
{
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
        output( 0, Log::General, Log::Debug, "log server shutdown" );
        break;
    case Connect:
    case Error:
    case Close:
        break;
    };
}


/*! Parses log messages from the input buffer. */

void LogServer::parse()
{
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
    if ( line.startsWith( "name " ) ) {
        d->name = line.mid( 5 );
        return;
    }
    else if ( line.startsWith( "shutdown" ) ) {
        close();
        return;
    }

    uint cmd = 0;
    uint msg = 0;

    cmd = line.find( ' ' );
    if ( cmd > 0 )
        msg = line.find( ' ', cmd+1 );
    if ( msg <= cmd+1 )
        return;

    String transaction( line.mid( 0, cmd ) );
    String priority( line.mid( cmd+1, msg-cmd-1 ) );
    String parameters( line.mid( msg+1 ) );

    int n = priority.find( '/' );
    if ( n < 0 )
        return;

    Log::Facility f = facility( priority.mid( 0, n ) );
    Log::Severity s = severity( priority.mid( n+1 ) );

    if ( s >= logLevel )
        output( transaction, f, s, parameters );
}


/*! This private function actually writes \a line to the log file with
    the \a tag, facility \a f, and severity \a s converted into their
    textual representations.
*/

void LogServer::output( String tag, Log::Facility f, Log::Severity s,
                        const String &line )
{
    String msg;
    msg.reserve( line.length() );

    msg.append( Log::facility( f ) );
    msg.append( "/" );
    msg.append( Log::severity( s ) );
    msg.append( ": " );
    msg.append( fn( d->id, 36 ) );
    msg.append( "/" );
    msg.append( tag );
    msg.append( ": " );
    msg.append( line );
    msg.append( "\n" );

    if ( logFile )
        logFile->write( msg );
    else
        fprintf( stderr, "%s", msg.cstr() );
}


/*! Tells all LogServer object to write log information to \a name
    from now on. (If the file has to be created, \a mode is used.)
*/

void LogServer::setLogFile( const String &name, const String &mode )
{
    uint m = 0;
    String s = mode;
    bool ok = false;

    if ( s.length() == 4 && s[0] == '0' )
        s = s.mid( 1 );

    if ( s.length() == 3 ) {
        if ( s[0] >= '0' && s[0] <= '9' &&
             s[1] >= '0' && s[1] <= '9' &&
             s[2] >= '0' && s[2] <= '9' )
        {
            m = ( s[0] - '0' ) * 0100 +
                ( s[1] - '0' ) * 010 +
                ( s[2] - '0' );
            ok = true;
        }

    }

    if ( !ok ) {
        ::log( "Invalid logfile-mode " + mode, Log::Disaster );
        return;
    }

    File * l;
    if ( name == "-" )
        l = new File( dup( 1 ) );
    else
        l = new File( name, File::Append, m );

    if ( !l->valid() ) {
        ::log( "Could not open log file " + name, Log::Disaster );
        return;
    }

    logFile = l;
    Allocator::addEternal( logFile, "logfile name" );
}


/*! Sets the log level to the Severity corresponding to \a l. */

void LogServer::setLogLevel( const String &l )
{
    logLevel = severity( l );
}


/*! Maps \a l to the corresponding Log::Facility value, and returns
    Log::General in case of error.

    This function is the inverse of Log::facility().
*/

Log::Facility LogServer::facility( const String &l )
{
    Log::Facility f = Log::General;

    switch ( l[0] ) {
    case 'i':
    case 'I':
        f = Log::IMAP;
        break;

    case 'c':
    case 'C':
        f = Log::Configuration;
        break;

    case 'd':
    case 'D':
        f = Log::Database;
        break;

    case 'a':
    case 'A':
        f = Log::Authentication;
        break;

    case 's':
    case 'S':
        if ( (l[1]|0x20) == 'm' )
            f = Log::SMTP;
        else
            f = Log::Server;
        break;

    default:
        f = Log::General;
        break;
    }
    return f;
}


/*! Maps \a l to the corresponding Log::Severity value, and returns
    Log::Info in case of error.

    This function is the inverse of Log::severity().
*/

Log::Severity LogServer::severity( const String &l )
{
    Log::Severity s = Log::Info;

    switch ( l[2] ) {
    case 'b':
    case 'B':
        s = Log::Debug;
        break;

    case 'f':
    case 'F':
        s = Log::Info;
        break;

    case 'g':
    case 'G':
        s = Log::Significant;
        break;

    case 'r':
    case 'R':
        s = Log::Error;
        break;

    case 's':
    case 'S':
        s = Log::Disaster;
        break;
    }
    return s;
}


/*! Logs a final line in the logfile and reopens it. The unused \a int
    argument exists because this function is used as a signal handler.
*/

void LogServer::reopen( int )
{
    if ( !logFile || logFile->name().isEmpty() )
        return;

    File * l = new File( logFile->name(), File::Append );
    if ( !l->valid() ) {
        ::log( "SIGHUP handler was unable to open new log file" +
               l->name(),
               Log::Disaster );
        EventLoop::shutdown(); // XXX: perhaps better to switch to syslog
    }
    ::log( "SIGHUP caught. Closing and reopening log file " + logFile->name(),
           Log::Info );
    delete logFile;
    logFile = l;
    ::log( "SIGHUP caught. Reopened log file " + logFile->name(),
           Log::Info );
}
