// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "log.h"

#include "scope.h"
#include "logger.h"
#include "string.h"

// gettimeofday
#include <sys/time.h>
// localtime
#include <time.h>
// sprintf
#include <stdio.h>


static bool disasters = false;
static String time();


void log( const String &s )
{
    Log *l = Scope::current()->log();

    if ( l )
        l->log(s);
}


void log( Log::Severity s, const String &t )
{
    Log *l = Scope::current()->log();

    if ( l )
        l->log( s, t );
}


/*! \class Log log.h
    The Log class sends log messages to the Log server.

    A Log object accepts messages via log() and sends them to the log
    server. The log server can be instructed to commit() all messages of
    or above a certain priority, logged since the last such instruction,
    and discard the others.

    If a Log is destroyed (or the program dies), all pending messages
    are committed to disk by the log server.
*/

/*! Constructs an empty Log object with facility \a f.
*/

Log::Log( Facility f )
    : fc( f )
{
    Log *l = Scope::current()->log();

    if ( !l )
        id = "1";
    else
        id = l->id + "/" + fn( l->children++ );
    children = 1;
}


/*! Logs \a l using severity \a s. \a l may not be written to disk
    right away; that depends on the log daemon's preferences.
*/

void Log::log( Severity s, const String &l )
{
    Logger * logger = Logger::logger();
    if ( logger == 0 )
        return;

    if ( s == Disaster )
        disasters = true;

    logger->send( id + " " + facility( fc ) + "/" + severity( s ) + " " +
                  time() + " " + l.stripCRLF() + "\r\n" );
}


/*! \fn void Log::log( const String &s )
    \overload Logs \a s at the default priority of Info.
*/


/*! Requests the log server to commit all log statements with severity
    \a s or more to disk. */

void Log::commit( Severity s )
{
    Logger * logger = Logger::logger();
    if ( logger == 0 )
        return;

    logger->send( id + " commit " +
                  facility( fc ) + "/" + severity( s ) + "\r\n" );
}


/*! Destroys a Log. Uncommitted messages are written to the log file. */

Log::~Log()
{
    commit( Debug );
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
    sprintf( result, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             t->tm_year + 1900, t->tm_mon+1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec,
             (int)tv.tv_usec/1000 );
    return result;
}


/*! This static function returns a string describing \a s. */

String Log::severity( Severity s )
{
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


/*! This static function returns a string describing \a f. */

String Log::facility( Facility f )
{
    String i;

    switch ( f ) {
    case Immediate:
        i = "immediate";
        break;
    case Configuration:
        i = "configuration";
        break;
    case Database:
        i = "database";
        break;
    case Authentication:
        i = "authentication";
        break;
    case IMAP:
        i = "imap";
        break;
    case SMTP:
        i = "smtp";
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
