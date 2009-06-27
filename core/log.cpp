// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "log.h"

#include "scope.h"
#include "logger.h"
#include "estring.h"
#include "configuration.h"

// sprintf, fprintf
#include <stdio.h>
// getpid()
#include <sys/types.h>
#include <unistd.h>


static bool disasters = false;
static Log::Severity logLevel = Log::Disaster;


static void setLogLevel()
{
    if ( logLevel != Log::Disaster )
        return;

    EString ll( Configuration::text( Configuration::LogLevel ) );
    if ( ll == Log::severity( Log::Disaster ) )
        logLevel = Log::Disaster;
    else if ( ll == Log::severity( Log::Error ) )
        logLevel = Log::Error;
    else if ( ll == Log::severity( Log::Significant ) )
        logLevel = Log::Significant;
    else if ( ll == Log::severity( Log::Info ) )
        logLevel = Log::Info;
    else if ( ll == Log::severity( Log::Debug ) )
        logLevel = Log::Debug;
    else
        logLevel = Log::Significant; // hm. silent failure.
}


void log( const EString &m, Log::Severity s )
{
    if ( s < logLevel )
        return;

    Scope * cs = Scope::current();
    Log *l = 0;
    if ( cs )
        l = cs->log();
    if ( l )
        l->log( m, s );
}


/*! \class Log log.h
    The Log class sends log messages to the Log server.

    A Log object accepts messages via log() and sends them to the log
    server.
*/

/*! Constructs a Log object the parent() that's currently in Scope. */

Log::Log()
    : children( 1 ), p( 0 )
{
    ::setLogLevel();
    Scope * cs = Scope::current();
    if ( cs )
        p = cs->log();
    if ( p )
        ide = p->id() + "/" + fn( p->children++ );
    else
        ide = EString::fromNumber( getpid() );
}


/*! Constructs a Log object with parent() \a parent. */

Log::Log( Log * parent )
    : children( 0 ), p( parent )
{
    ::setLogLevel();
    if ( p )
        ide = p->id() + "/" + fn( p->children++ );
    else
        ide = EString::fromNumber( getpid() );
}


/*! Logs \a m using severity \a s. What happens to the message depends
    on the type of Logger used, and the log server configuration.
*/

void Log::log( const EString &m, Severity s )
{
    Logger * l = Logger::global();
    if ( s == Disaster ) {
        disasters = true;
        EString n = "Archiveopteryx";
        if ( l )
            n = l->name();
        fprintf( stderr, "%s: %s\n", n.cstr(), m.simplified().cstr() );
    }

    if ( !l )
        return;

    l->send( ide, s, m );
}


/*! This static function returns a string describing \a s. */

const char * Log::severity( Severity s )
{
    const char *i = 0;

    switch ( s ) {
    case Log::Debug:
        i = "debug";
        break;
    case Log::Info:
        i = "info";
        break;
    case Log::Significant:
        i = "significant";
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


/*! Returns the identity of this log; this is a string which can be
    used to locate log data in the logfile.
*/

EString Log::id()
{
    return ide;
}


/*! Returns a pointer to the Log that was in effect when this object
    was created. This object's id() is based on the parent's id().

    The return value if parent() may be 0.
*/

Log * Log::parent() const
{
    return p;
}


/*! Returns true if this object is \a other or a child of \a other
    (through the parent() chain), and false if not.
*/

bool Log::isChildOf( Log * other ) const
{
    const Log * l = this;
    while ( l && l != other )
        l = l->parent();
    if ( l )
        return true;
    return false;
}
