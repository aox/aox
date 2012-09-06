// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "beeper.h"

#include "buffer.h"


/*! \class Beeper beeper.h

  The Beeper class sends a single byte every five seconds. That's all
  it does.

  The corresponding ChildWatcher listens for these bytes, and will
  kill the process containing the Beeper if the byte stream ceases. In
  essence, a dead man's switch.
*/


/*! Constructs a Beeper for \a fd. The beeper immeditely starts doing
    its work, with no further instruction needed.
 */

Beeper::Beeper( int fd )
    : Connection( fd, Connection::Beeper )
{
    setTimeoutAfter( 5 );
}


void Beeper::react( Event e )
{
    if ( e != Timeout )
        return;

    writeBuffer()->append( "\b" );
    setTimeoutAfter( 5 );
}
