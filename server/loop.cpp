#include "loop.h"

#include "list.h"
#include "connection.h"
#include "buffer.h"
#include "string.h"
#include "log.h"
#include "scope.h"
#include "arena.h"
#include "test.h"
#include "sys.h"

// time
#include <time.h>
// errno
#include <errno.h>
// struct timeval, fd_set
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
// read, select
#include <unistd.h>


static bool armageddon = false;

static SortedList< Connection > connections;
static Arena loopArena;


/*! \class Loop loop.h
    Dispatches events to connections.

    The event loop maintains a list of connections that are waiting for
    something to happen, and notifies them of any events that do occur.
*/


/*! Dispatches events to connections until Loop::shutdown() is called. */

void Loop::start()
{
    SortedList< Connection >::Iterator it;

    Scope x( &loopArena );

    while ( !armageddon ) {
        Connection *c;

        int timeout = INT_MAX;
        int maxfd = -1;
        if ( connections.count() > 0 )
            maxfd = connections.last()->fd();

        fd_set r, w;
        FD_ZERO( &r );
        FD_ZERO( &w );

        // Figure out what events each connection wants.

        it = connections.first();
        while ( it ) {
            c = it++;

            if ( !c->active() )
                continue;

            // This is so that Halfpipes can be closed by their partner.
            if ( c->state() == Connection::Closing &&
                 !c->canWrite() )
            {
                Loop::removeConnection( c );
                delete c;
                continue;
            }

            int fd = c->fd();
            if ( c->canRead() && c->state() != Connection::Closing )
                FD_SET( fd, &r );
            if ( c->canWrite() || c->state() == Connection::Connecting )
                FD_SET( fd, &w );
            if ( c->timeout() > 0 && c->timeout() < timeout )
                timeout = c->timeout();
        }

        // Wait for something interesting to happen.

        struct timeval tv;
        tv.tv_sec = timeout - time( 0 );
        tv.tv_usec = 0;

        if ( tv.tv_sec < 1 )
            tv.tv_sec = 1;
        if ( tv.tv_sec > 1800 )
            tv.tv_sec = 1800;

        int n = select( maxfd+1, &r, &w, 0, &tv );
        time_t now = time( 0 );

        if ( n < 0 ) {
            // XXX: We should handle signals appropriately.
            if ( errno == EINTR )
                continue;

            log( "Main loop: select() broke" );
            exit( 0 );
        }

        // Figure out what each connection cares about.

        it = connections.first();
        while ( it ) {
            c = it++;
            int fd = c->fd();
            dispatch( c, FD_ISSET( fd, &r ), FD_ISSET( fd, &w ), now );
        }

        // XXX: We should handle armageddon better.
        if ( armageddon ) {
            it = connections.last();
            while ( it ) {
                c = connections.take( it-- );
                {
                    Scope x( c->arena() );
                    c->react( Connection::Shutdown );
                    c->write();
                }
                delete c;
            }
        }
    }
}


/*! Dispatches events to the connection \a c, based on its current
    state, the time \a now and the results from select: \a r is true
    if the FD may be read, and \a w is true if we know that the FD may
    be written to. If \a now is past that Connection's timeout, we
    must sent a Timeout event.
*/

void Loop::dispatch( Connection *c, bool r, bool w, int now )
{
    Scope x( c->arena() );

    try {
        if ( c->timeout() != 0 && now >= c->timeout() ) {
            c->setTimeout( 0 );
            c->react( Connection::Timeout );
            w = true;
        }

        if ( c->state() == Connection::Connecting ) {
            bool error = false;
            bool connected = false;

            if ( ( w && !r ) || c->isPending( Connection::Connect ) ) {
                connected = true;
            }
            else if ( c->isPending( Connection::Error ) ) {
                error = true;
            }
            else if ( w && r ) {
                // This might indicate a connection error, or a successful
                // connection with outstanding data. (Stevens suggests the
                // zero-length read to disambiguate, cf. UNPv1 15.4.)
                if ( ::read( c->fd(), 0, 0 ) == 0 )
                    connected = true;
                else
                    error = true;
            }

            if ( connected ) {
                c->setState( Connection::Connected );
                c->react( Connection::Connect );
                w = true;
            }
            else if ( error ) {
                c->react( Connection::Error );
                c->setState( Connection::Closing );
                w = r = false;
            }
        }

        if ( r ) {
            c->read();
            c->react( Connection::Read );

            if ( !c->canRead() ) {
                c->react( Connection::Close );
                c->setState( Connection::Closing );
            }

            w = true;
        }

        if ( w )
            c->write();
    }
    catch ( Exception e ) {
        log( Log::Error, "While processing " + c->description() + ":" );
        switch (e) {
        case Range:
            log( Log::Error, "Out-of-range memory access." );
            break;
        case Memory:
            log( Log::Error, "Out of memory." );
            break;
        case FD:
            log( Log::Error, "FD error." );
            break;
        };
        c->close();
    }

    if ( c->state() == Connection::Closing && !c->canWrite() )
        c->close();

    if ( !c->valid() ) {
        Loop::removeConnection( c );
        delete c;
    }
}


/*! Makes the main loop send the Shutdown even to all Connection
    objects and afterwards delete them.
*/

void Loop::shutdown()
{
    armageddon = true;
}


/*! Registers the connection \a c for event notifications in future. */

void Loop::addConnection( Connection *c )
{
    Scope x( &loopArena );
    connections.insert( c );
}

/*! Removes (and destroys) the connection \a c from the event loop. */

void Loop::removeConnection( Connection *c )
{
    Scope x( &loopArena );
    connections.take( connections.find(c) );
}
