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
    lines with \a name.
*/

StderrLogger::StderrLogger( const String & name )
    : Logger(), n( name )
{
}


void StderrLogger::send( const String &,
                      Log::Facility, Log::Severity s,
                      const String & m )
{
    // Log already does this
    if ( s == Log::Error )
        fprintf( stderr, "%s: %s\n", name().cstr(), m.cstr() );

    // Debug we ignore, Info we ignore for now.

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
