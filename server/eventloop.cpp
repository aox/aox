// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "eventloop.h"

#include "scope.h"
#include "allocator.h"
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
        : log( new Log( Log::Server ) ),
          stop( false ), shutdown( false )
    {}

    Log *log;
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
    Scope x( d->log );

    if ( d->connections.find( c ) )
        // if we're going to be silent, let's be honest about it
        return;

    d->connections.insert( c );
    if ( c->type() != Connection::LogClient )
        log( "Added " + c->description(), Log::Debug );
}


/*! Removes \a c from this EventLoop's list of active
    Connections.

    Since this is the last time the Connection is reachable,
    removeConnection() calls Connection::commit() as well.
*/

void EventLoop::removeConnection( Connection *c )
{
    Scope x( d->log );

    SortedList< Connection >::Iterator it( d->connections.find( c ) );
    if ( !it )
        return;

    c->commit();
    d->connections.take( it );
    if ( c->type() != Connection::LogClient )
        log( "Removed " + c->description(), Log::Debug );
}


/*! Starts the EventLoop and runs it until stop() is called. */

void EventLoop::start()
{
    Scope x( d->log );
    time_t gc = 0;

    log( "Starting event loop", Log::Debug );

    while ( !d->stop ) {
        Connection *c;

        int timeout = INT_MAX;
        int maxfd = -1;
        if ( d->connections.count() > 0 )
            maxfd = d->connections.last()->fd();

        fd_set r, w;
        FD_ZERO( &r );
        FD_ZERO( &w );

        // Figure out what events each connection wants.

        SortedList< Connection >::Iterator it( d->connections.first() );
        while ( it ) {
            c = it;

            if ( c->active() ) {
                int fd = c->fd();
                if ( c->canRead() && c->state() != Connection::Closing )
                    FD_SET( fd, &r );
                if ( c->canWrite() || c->state() == Connection::Connecting )
                    FD_SET( fd, &w );
                if ( c->timeout() > 0 && c->timeout() < timeout )
                    timeout = c->timeout();
            }

            ++it;
        }

        // Look for interesting input

        struct timeval tv;
        tv.tv_sec = timeout - time( 0 );
        tv.tv_usec = 0;

        if ( tv.tv_sec < 1 )
            tv.tv_sec = 1;
        if ( tv.tv_sec > 60 )
            tv.tv_sec = 60;

        int n = select( maxfd+1, &r, &w, 0, &tv );
        time_t now = time( 0 );

        if ( n < 0 ) {
            // XXX: We should handle signals appropriately. (How is
            // that, exactly? We don't use the things at all.)
            if ( errno == EINTR )
                return;

            // XXX: And this is highly suboptimal, too. (Why?)
            log( "EventLoop: select() returned errno " + fn( errno ),
                 Log::Disaster );
            commit();
            exit( 0 );
        }
        if ( now - gc > 60 ) {
            Allocator::free();
            gc = time( 0 );
        }

        // Figure out what each connection cares about.

        it = d->connections.first();
        while ( it ) {
            c = it;
            int fd = c->fd();
            if ( fd >= 0 )
                dispatch( c, FD_ISSET( fd, &r ), FD_ISSET( fd, &w ), now );
            ++it;
        }
        commit();
    }

    // This is for event loop shutdown. A little brutal. Proper
    // shutdown should first get rid of listeners, then a (long)
    // while later call this. Note that there is similar code in
    // ConsoleLoop.
    if ( d->shutdown ) {
        log( "Shutting down event loop", Log::Debug );
        SortedList< Connection >::Iterator it( d->connections.first() );
        while ( it ) {
            try {
                Scope x( it->log() );
                if ( it->state() == Connection::Connected )
                    it->react( Connection::Shutdown );
                if ( it->state() == Connection::Connected )
                    it->write();
            } catch ( Exception e ) {
                // we don't really care at this point, do we?
            }
            ++it;
        }
    }

    log( "Event loop stopped", Log::Debug );
    commit();
}


/*! Dispatches events to the connection \a c, based on its current
    state, the time \a now and the results from select: \a r is true
    if the FD may be read, and \a w is true if we know that the FD may
    be written to. If \a now is past that Connection's timeout, we
    must sent a Timeout event.
*/

void EventLoop::dispatch( Connection *c, bool r, bool w, int now )
{
    try {
        Scope x( c->log() );
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
                // any debugging prior to connect can now be flushed
                c->commit();
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
        String s;
        switch (e) {
        case Range:
            s = "Out-of-range memory access";
            break;
        case Memory:
            s = "Out of memory";
            break;
        case FD:
            s = "FD error";
            break;
        };
        s.append( " while processing " + c->description() );
        d->log->log( s, Log::Error );
        c->close();
    }

    if ( c->state() == Connection::Closing && !c->canWrite() )
        c->close();
    if ( !c->valid() )
        delete c;
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


/*! Closes all Connections except \a c1 and \a c2. This helps TlsProxy
    do its work.
*/

void EventLoop::closeAllExcept( Connection * c1, Connection * c2 )
{
    SortedList< Connection >::Iterator it( d->connections.first() );
    while ( it ) {
        Connection *c = it;
        if ( c != c1 && c != c2 ) {
            removeConnection( c );
            c->close();
        }
        ++it;
    }
}


/*! Flushes the write buffer of all connections. */

void EventLoop::flushAll()
{
    SortedList< Connection >::Iterator it( d->connections.first() );
    while ( it ) {
        it->write();
        ++it;
    }
}
