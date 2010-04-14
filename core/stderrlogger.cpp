// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "stderrlogger.h"

#include "log.h"

#include <stdio.h> // fprintf
#include <stdlib.h> // exit
#include <sysexits.h> // all the exit codes

/*! \class StderrLogger stderrlogger.h

    The StderrLogger logs errors and disaster output to stderr and
    exits the program immediately in case of a disaster. It is used by
    some command-line programs.
*/


/*! Creates a logger named \a name. The object will preface its output
    lines with \a name. If \a verbosity is 0, info messages are
    suppressed. If \a verbosity is 0 or 1, debug messages are
    suppressed.
*/

StderrLogger::StderrLogger( const EString & name, uint verbosity )
    : Logger(), n( name ), v( verbosity )
{
    Log::Severity ls;

    if ( v == 0 )
        ls = Log::Significant;
    else if ( v == 1 )
        ls = Log::Info;
    else
        ls = Log::Debug;

    Log::setLogLevel( ls );
}


void StderrLogger::send( const EString &, Log::Severity s, const EString & m )
{
    // we don't need to handle Disaster, Log already has done that
    if ( s != Log::Disaster ) {
        fprintf( stderr, "%s: %s\n", name().cstr(), m.cstr() );
    }
    else {
        fprintf( stderr, "%s: Fatal error. Exiting.\n", name().cstr() );
        exit( EX_UNAVAILABLE );
    }
}


/*! Returns the name of this object, as supplied to the constructor. */

EString StderrLogger::name() const
{
    return n;
}
