#include "eventloop.h"

#include "arena.h"
#include "scope.h"
#include "list.h"
#include "connection.h"
#include "buffer.h"
#include "string.h"
#include "log.h"
#include "sys.h"

// time
#include <time.h>
// errno
#include <errno.h>
// struct timeval, fd_set
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
// getsockopt, SOL_SOCKET, SO_ERROR
#include <sys/socket.h>
// read, select
#include <unistd.h>


class LoopData {
public:
    LoopData()
        : arena( new Arena ), stop( false ), shutdown( false )
    {}

    Arena *arena;
    bool stop, shutdown;
    SortedList< Connection > connections;
};


/*! \class EventLoop eventloop.h
    This class dispatches event notifications to a list of Connections.

    An EventLoop maintains a list of participating Connection objects,
    and periodically informs them about any events (e.g., read/write,
    errors, timeouts) that occur. The loop continues until something
    calls stop() or shutdown().

    The main user of this class is the global event Loop.
*/

/*! Creates a new EventLoop. */

EventLoop::EventLoop()
    : d( new LoopData )
{
}


/*! Adds \a c to this EventLoop's list of active Connections. */

void EventLoop::addConnection( Connection *c )
{
    Scope x( d->arena );
    d->connections.insert( c );
}


/*! Removes \a c from this EventLoop's list of active Connections. */

void EventLoop::removeConnection( Connection *c )
{
    Scope x( d->arena );
    d->connections.take( d->connections.find( c ) );
}


/*! Instructs this EventLoop to stop immediately, leaving participating
    Connections unchanged.
*/

void EventLoop::stop()
{
    d->stop = true;
}


/*! Instructs this EventLoop to perform an orderly shutdown, by sending
    each participating Connection a Shutdown event before closing, and
    then deleting each one.
*/

void EventLoop::shutdown()
{
    d->shutdown = true;
    d->stop = true;
}


/*! Starts the EventLoop. */

void EventLoop::start()
{
    Scope x( d->arena );

    while ( !d->stop ) {
        SortedList< Connection >::Iterator it;
        Connection *c;

        int timeout = INT_MAX;
        int maxfd = -1;
        if ( d->connections.count() > 0 )
            maxfd = d->connections.last()->fd();

        fd_set r, w;
        FD_ZERO( &r );
        FD_ZERO( &w );

        // Figure out what events each connection wants.

        it = d->connections.first();
        while ( it ) {
            c = it++;

            if ( !c->active() )
                continue;

            // This is so that Halfpipes can be closed by their partner.
            if ( c->state() == Connection::Closing &&
                 !c->canWrite() )
            {
                removeConnection( c );
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

        it = d->connections.first();
        while ( it ) {
            c = it++;
            int fd = c->fd();
            dispatch( c, FD_ISSET( fd, &r ), FD_ISSET( fd, &w ), now );
        }

        // XXX: We should handle armageddon better.
        if ( d->shutdown ) {
            it = d->connections.last();
            while ( it ) {
                c = d->connections.take( it-- );
                {
                    Scope x( c->arena() );
                    c->react( Connection::Shutdown );
                    c->write();
                }
                if ( c->type() != Connection::LoggingClient )
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

void EventLoop::dispatch( Connection *c, bool r, bool w, int now )
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
                // getsockopt to disambiguate the two, cf. UNPv1 15.4.)
                int errval;
                int errlen = sizeof( int );
                ::getsockopt( c->fd(), SOL_SOCKET, SO_ERROR, (void *)&errval,
                              (socklen_t *)&errlen );

                if ( errval == 0 )
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
        removeConnection( c );
        delete c;
    }
}


/*!

*/

void EventLoop::killAllExcept( Connection * c1, Connection * c2 )
{
    SortedList< Connection >::Iterator it = d->connections.first();
    while ( it ) {
        Connection * c = it;
        it++;
        if ( c == c1 || c == c2 ) {
            // we keep those two.
        }
        else {
            removeConnection( c );
            delete c;
        }
    }
    
}
