#include "log.h"

#include "arena.h"
#include "scope.h"
#include "string.h"
#include "buffer.h"
#include "endpoint.h"
#include "configuration.h"
#include "loop.h"

// exit
#include <stdlib.h>
// *printf, stderr
#include <stdio.h>
// EX_UNAVAILABLE
#include <sysexits.h>
// gettimeofday
#include <sys/time.h>
// localtime
#include <time.h>


static Log * globalLog = 0;
static bool disasters = false;
static class LogClient * client = 0;
static Arena logArena;
static uint loggers = 0;
static String time();


// This is our persistent connection to the log server.
class LogClient
    : public Connection
{
public:
    LogClient( int s )
        : Connection( s )
    {}

    ~LogClient() {
        client = 0;
    }

    // The log server isn't supposed to send us anything.
    void react( Event e ) {
        switch ( e ) {
        case Connect:
        case Timeout:
        case Shutdown:
            break;
        case Read:
        case Close:
        case Error:
            Loop::shutdown();
            break;
        }
    }
};


/*! \class Log log.h
    The Log class sends log messages to the Log server.

    A Log object accepts messages via log() and sends them to the log
    server. The log server can be instructed to commit() all messages of
    or above a certain priority, logged since the last such instruction,
    and discard the others.

    If a Log is destroyed (or the program dies), all pending messages
    are committed to disk by the log server.

    Log::global()->log( "..." ) is useful for server-global messages.
*/

/*! This function creates a LogClient and connects to the Log server,
    such that logging can work.
*/

void Log::setup()
{
    Scope x( &logArena );
    Configuration::Text logHost( "loghost", "127.0.0.1" );
    Configuration::Scalar logPort( "logport", 2054 );
    Endpoint e( logHost, logPort );

    if ( !e.valid() ) {
        fprintf( stderr, "LogClient: Unable to parse address <%s> port %d\n",
                 ((String)logHost).cstr(), (int)logPort );
        exit( EX_USAGE );
    }

    client = new LogClient( Connection::socket( e.protocol() ) );
    client->setBlocking( true );
    if ( client->connect(e) < 0 ) {
        fprintf( stderr, "LogClient: Unable to connect to log server %s\n",
                 String(e).cstr() );
        perror( "LogClient: connect() returned" );
        exit( EX_UNAVAILABLE );
    }

    client->setBlocking( false );
    Loop::addConnection( client );
}


/*! Constructs an empty Log object that can write to the Log. */

Log::Log()
    : id( loggers++ )
{
}


/*! Logs \a l using severity \a s. \a l may not be written to disk
    right away; that depends on the log daemon's preferences.
*/

void Log::log( Severity s, const String &l )
{
    if ( client == 0 )
        return;

    if ( s == Disaster )
        disasters = true;

    // XXX: what we really want is to get rid of CRLF, not call
    // String::simplified(). maybe later
    client->enqueue( String::fromNumber( id, 36 ) + " " +
                     severity( s ) + " " + time() + " " +
                     l.simplified() + "\r\n" );
    client->write();
}


/*! Requests the log server to commit all log statements with severity
    \a s or more to disk. */

void Log::commit( Severity s )
{
    if ( client == 0 )
        return;

    client->enqueue( String::fromNumber( id, 36 ) + " commit " +
                     severity( s ) + "\r\n" );
    client->write();
}


/*! Destroys a Log. Uncommitted messages are written to the log file. */

Log::~Log()
{
    commit( Debug );

    if ( this == globalLog )
        globalLog = 0;
}


/*! Returns a pointer to the global logger, which is used for
    server-global messages.
*/

Log * Log::global()
{
    if ( !globalLog ) {
        Scope x( &logArena );
        globalLog = new Log();
    }
    return globalLog;
}


/* This static function returns a nicely-formatted timestamp. */

static String time()
{
    struct timeval tv;
    struct timezone tz;
    if ( ::gettimeofday( &tv, &tz ) < 0 )
        return "";
    struct tm * t = localtime( (const time_t *)&tv.tv_sec );

    // yuck.
    char result[32];
    sprintf( result, "%04d:%02d:%02d %02d:%02d:%02d.%03d",
             t->tm_year + 1900, t->tm_mon+1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec,
             (int)tv.tv_usec/1000 );
    return result;
}


/*! This static function returns a string describing \a s. */

String Log::severity( Severity s )
{
    // make the logd protocol independent of the enum values
    String i;
    switch ( s ) {
    case Log::Debug:
        i = "debug";
        break;
    case Log::Info:
        i = "info";
        break;
    case Log::Error:
        i = "error";
        break;
    case Log::Disaster:
        i = "disaster";
        break;
    }
    return i;
}


/*! Returns true if at least one disaster has been logged (on any Log
    object), and false if none have been.

    The disaster need not be committed - disastersYet() returns true as
    soon as log() has been called for a disastrous error.
*/

bool Log::disastersYet()
{
    return disasters;
}


/* Uses the current scope log to log the message \a s. */

void log( const String & s )
{
    Log * l = Scope::current()->log();

    if ( l )
        l->log(s);
}
