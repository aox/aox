// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "log.h"

#include "scope.h"
#include "logger.h"
#include "string.h"

// sprintf, fprintf
#include <stdio.h>


static bool disasters = false;


void log( const String &m, Log::Severity s )
{
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

/*! Constructs an empty Log object with facility \a f. */

Log::Log( Facility f )
    : fc( f )
{
    Scope * cs = Scope::current();
    Log *l = 0;
    if ( cs )
        l = cs->log();
    if ( l )
        ide = l->id() + "/" + fn( l->children++ );
    else
        ide = "1";
    children = 1;
}


/*! Changes this Log's facility to \a f. */

void Log::setFacility( Facility f )
{
    fc = f;
}


/*! Logs \a m using severity \a s. What happens to the message depends
    on the type of Logger used, and the log server configuration.
*/

void Log::log( const String &m, Severity s )
{
    Logger *l = Logger::global();
    if ( s == Disaster ) {
        disasters = true;
        String n = "Archiveopteryx";
        if ( l )
            n = l->name();
        fprintf( stderr, "%s: %s\n", n.cstr(), m.simplified().cstr() );
    }

    if ( !l )
        return;

    l->send( ide, fc, s, m );
}


/*! This static function returns a string describing \a s. */

const char *Log::severity( Severity s )
{
    const char *i = 0;

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

const char *Log::facility( Facility f )
{
    const char *i = 0;

    switch ( f ) {
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
    case Server:
        i = "server";
        break;
    case General:
        i = "general";
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

String Log::id()
{
    return ide;
}
