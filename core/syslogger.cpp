// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "syslogger.h"

#include "string.h"

#include <syslog.h>


/*! \class Syslogger syslogger.h

  The Syslogger class logs all Oryx Log messages using the unix syslog
  subsystem. It's rather primitive, and is only meant as a band-aid
  for code that cannot connect to the LogServer.

  Syslogger does not delay logging until Log::commit() is called, and
  at present it even syslogs the Log::commit() as text. The latter is
  a bug, the former is valuable and desirable simplicity.
*/


/*! Constructs an Syslogger for program \a name. \a name will appear
    in the syslog along with the pid.*/

Syslogger::Syslogger( const char * name )
    : Logger()
{
    ::openlog( name, LOG_PID, LOG_MAIL );
}


/*! Logs the entire line \a s using a suitable priority. */

void Syslogger::send( const String & s )
{
    String tmp( s.stripCRLF() );
    int priority = LOG_ALERT;
    int i = s.find( " " );
    if ( i >= 0 ) {
        i++;
        if ( tmp[i] == 'i' )
            priority = LOG_INFO;
        else if ( tmp[i] == 'e' )
            priority = LOG_ERR;
        else if ( tmp[i] == 'd' && tmp[i+1] == 'e' )
            priority = LOG_DEBUG;
        else if ( tmp[i] == 'd' && tmp[i+1] == 'i' )
            priority = LOG_CRIT;
    }

    ::syslog( LOG_INFO, "%s", tmp.cstr() );
}
