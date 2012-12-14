// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "childwatcher.h"

#include "buffer.h"

#include <sys/types.h>
#include <signal.h>


/*! \class ChildWatcher childwatcher.h

    The ChildWatcher class watches the Beeper output from a child, and
    kills the child brutally if it isn't well-behaved.

    Quite likely the child is dead already when that happens, either
    deadlocked or livelocked. But we have to free up the CPU and make
    whoever is using the child reconnect.
*/

/*! Constructs a ChildWatcher for \a fd and \a process. No further
    setup is necessary.
*/

ChildWatcher::ChildWatcher( int fd, int process )
    : Connection( fd, Connection::ChildWatcher ), pid( process ), late( 0 )
{
    setTimeoutAfter( 5 );
}


void ChildWatcher::react( Event e )
{
    if ( e == Read && readBuffer()->size() ) {
        readBuffer()->remove( readBuffer()->size() );
        late = 0;
        setTimeoutAfter( 5 );
    }
    else if ( e == Timeout ) {
        switch ( late ) {
        case 0:
            late++;
            setTimeoutAfter( 5 );
            break;
        case 1:
            ::kill( pid, SIGTERM );
            setTimeoutAfter( 5 );
            break;
        default:
            ::kill( pid, SIGKILL );
            break;
        }
    }
}
