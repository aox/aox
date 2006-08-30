// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "stderrlogger.h"

#include <stdio.h> // fprintf
#include <stdlib.h> // exit


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

StderrLogger::StderrLogger( const String & name, uint verbosity )
    : Logger(), n( name ), v( verbosity )
{
}


void StderrLogger::send( const String &,
                      Log::Facility, Log::Severity s,
                      const String & m )
{
    // we don't need to handle Disaster, Log already has done that
    if ( s == Log::Error ||
         ( s == Log::Info && v >= 1 ) ||
         ( s == Log::Debug && v >= 2 ) ) 
        fprintf( stderr, "%s: %s\n", name().cstr(), m.cstr() );

    // and in case of a disaster, we quit. the hard way.
    if ( s == Log::Disaster ) {
        fprintf( stderr, "%s: Fatal error. Exiting.\n", name().cstr() );
        exit( 1 );
    }
}


/*! Returns the name of this object, as supplied to the constructor. */

String StderrLogger::name() const
{
    return n;
}
