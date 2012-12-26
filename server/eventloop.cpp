// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "eventloop.h"

#include "connection.h"
#include "allocator.h"
#include "buffer.h"
#include "estring.h"
#include "server.h"
#include "scope.h"
#include "timer.h"
#include "graph.h"
#include "event.h"
#include "list.h"
#include "log.h"

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
// ioctl, FIONREAD
#include <sys/ioctl.h>

// memset (for FD_* under OpenBSD)
#include <string.h>


static bool freeMemorySoon;


static EventLoop * loop;


class LoopData
    : public Garbage
{
public:
    LoopData()
        : log( new Log ), startup( false ),
          stop( false ), limit( 0 )
    {}

    Log *log;
    bool startup;
    bool stop;
    List< Connection > connections;
    List< Timer > timers;
    uint limit;

    class Stopper
        : public EventHandler
    {
    public:
        Stopper( uint s ): stage2( false ) {
            (void)new Timer( this, s );
            if ( s <= 10 )
                stage2 = true;
        }
        void execute() {
            if ( !EventLoop::global() || EventLoop::global()->inShutdown() )
                return;
            if ( stage2 )
                EventLoop::global()->stop();
            else
                EventLoop::global()->stop( 10 );
        }
        bool stage2;
    };
};


/*! \class EventLoop eventloop.h
    This class dispatches event notifications to a list of Connections.

    An EventLoop maintains a list of participating Connection objects,
    and periodically informs them about any events (e.g., read/write,
    errors, timeouts) that occur. The loop continues until something
    calls stop().
*/


/*! Creates the global EventLoop object or, if \a l is non-zero, sets
    the global EventLoop to \a l. This function expects to be called
    very early during the startup sequence.
*/

void EventLoop::setup( EventLoop * l )
{
    ::loop = l;
    if ( !l )
        ::loop = new EventLoop;
    Allocator::addEternal( ::loop, "global event loop" );
}


/*! Creates a new EventLoop. */

EventLoop::EventLoop()
    : d( new LoopData )
{
}


/*! Exists only to avoid compiler warnings. */

EventLoop::~EventLoop()
{
}


/*! Adds \a c to this EventLoop's list of active Connections.

    If shutdown() has been called already, addConnection() ignores \a
    c, so that shutdown proceeds unhampered. This is likely to disturb
    \a c a little, but it's better than the alternative: Aborting the
    shutdown.
*/

void EventLoop::addConnection( Connection * c )
{
    if ( d->stop ) {
        log( "Cannot add new Connection objects during shutdown",
             Log::Error );
        return;
    }

    Scope x( d->log );

    if ( d->connections.find( c ) )
        return;

    d->connections.prepend( c );
    setConnectionCounts();
}


/*! Removes \a c from this EventLoop's list of active
    Connections.
*/

void EventLoop::removeConnection( Connection * c )
{
    Scope x( d->log );

    if ( d->connections.remove( c ) == 0 )
        return;
    setConnectionCounts();

    // if this is a server, with external connections, and we just
    // closed the last external connection, then we shut down
    // nicely. otherwise, we just remove the specified connection,
    // with no magic.

    if ( c->hasProperty( Connection::Internal ) )
        return;

    if ( d->stop )
        return;

    List< Connection >::Iterator it( d->connections );
    while ( it ) {
        if ( !it->hasProperty( Connection::Internal ) )
            return;
        ++it;
    }
    stop( 2 );
}


/*! Returns a (non-zero) pointer to the list of Connections that have
    been added to this EventLoop.
*/

List< Connection > *EventLoop::connections() const
{
    return &d->connections;
}


static GraphableNumber * sizeinram = 0;

static const uint gcDelay = 30;


/*! Starts the EventLoop and runs it until stop() is called. */

void EventLoop::start()
{
    Scope x( d->log );
    time_t gc = time(0);
    bool haveLoggedStartup = false;

    log( "Starting event loop", Log::Debug );

    while ( !d->stop && !Log::disastersYet() ) {
        if ( !haveLoggedStartup && !inStartup() ) {
            if ( !Server::name().isEmpty() )
                log( Server::name() + ": Server startup complete",
                     Log::Significant );
            haveLoggedStartup = true;
        }

        Connection * c;

        uint timeout = gcDelay;
        int maxfd = -1;

        fd_set r, w;
        FD_ZERO( &r );
        FD_ZERO( &w );

        // Figure out what events each connection wants.

        List< Connection >::Iterator it( d->connections );
        while ( it ) {
            c = it;
            ++it;

            int fd = c->fd();
            if ( fd < 0 ) {
                removeConnection( c );
            }
            else if ( c->type() == Connection::Listener && inStartup() ) {
                // we don't accept new connections until we've
                // completed startup
            }
            else {
                if ( fd > maxfd )
                    maxfd = fd;
                FD_SET( fd, &r );
                if ( c->canWrite() ||
                     c->state() == Connection::Connecting ||
                     c->state() == Connection::Closing )
                    FD_SET( fd, &w );
                if ( c->timeout() > 0 && c->timeout() < timeout )
                    timeout = c->timeout();
            }
        }

        // Figure out whether any timers need attention soon

        List< Timer >::Iterator t( d->timers );
        while ( t ) {
            if ( t->active() && t->timeout() < timeout )
                timeout = t->timeout();
            ++t;
        }

        // Look for interesting input

        struct timeval tv;
        tv.tv_sec = timeout - time( 0 );
        tv.tv_usec = 0;

        if ( tv.tv_sec < 0 )
            tv.tv_sec = 0;
        if ( tv.tv_sec > 60 )
            tv.tv_sec = 60;

        // we never ask the OS to sleep shorter than .2 seconds
        if ( tv.tv_sec < 1 )
            tv.tv_usec = 200000;

        if ( select( maxfd+1, &r, &w, 0, &tv ) < 0 ) {
            // r and w are undefined. we clear them, and dispatch()
            // won't jump to conclusions
            FD_ZERO( &r );
            FD_ZERO( &w );
        }
        time_t now = time( 0 );

        // Graph our size before processing events
        if ( !sizeinram )
            sizeinram = new GraphableNumber( "memory-used" );
        sizeinram->setValue( Allocator::inUse() + Allocator::allocated() );

        // Any interesting timers?

        if ( !d->timers.isEmpty() ) {
            uint now = time( 0 );
            t = d->timers.first();
            while ( t ) {
                Timer * tmp = t;
                ++t;
                if ( tmp->active() && tmp->timeout() <= now )
                    tmp->execute();
            }
        }

        // Figure out what each connection cares about.

        it = d->connections.first();
        while ( it ) {
            c = it;
            ++it;
            int fd = c->fd();
            if ( fd >= 0 ) {
                dispatch( c, FD_ISSET( fd, &r ), FD_ISSET( fd, &w ), now );
                FD_CLR( fd, &r );
                FD_CLR( fd, &w );
            }
            else {
                removeConnection( c );
            }
        }

        // Graph our size after processing all the events too

        sizeinram->setValue( Allocator::inUse() + Allocator::allocated() );

        // Collect garbage if someone asks for it, or if we've passed
        // the memory usage goal. This has to be at the end of the
        // scope, since anything referenced by local variables might
        // be freed here.

        if ( !d->stop ) {
            if ( !::freeMemorySoon ) {
                uint a = Allocator::inUse() + Allocator::allocated();
                if ( now < gc ) {
                    // time went backwards, best to be paranoid
                    ::freeMemorySoon = true;
                }
                else if ( d->limit ) {
                    // if we have a set limit, and memory usage is
                    // above the limit, then we have to free memory
                    // soon.  gcDelay is the basic period.

                    // if we're below the limit, we don't modify the
                    // limit. if we're above, but below 2x, we halve
                    // the limit (right-shift by one bit). if we're at
                    // 2-3x, we right-shift by two. if we're at 3-4x,
                    // we right-shift by three, etc.

                    // if memory usage is extreme enough we'll collect
                    // garbage every second.
                    uint factor = a / d->limit;
                    uint period = gcDelay >> factor;
                    if ( (uint)(now - gc) > period )
                        ::freeMemorySoon = true;
                }
                else {
                    // if we don't have a set limit, we try to stay
                    // below 4MB, but collect garbage no more than
                    // once per second.
                    if ( a > 4*1024*1024 && now > gc )
                        ::freeMemorySoon = true;
                }
            }
            if ( ::freeMemorySoon ) {
                Allocator::free();
                gc = time( 0 );
                ::freeMemorySoon = false;
            }
        }
    }

    // This is for event loop shutdown. A little brutal. With any
    // luck, the listeners have been closed long ago and this is just
    // for those who wouldn't disconnect voluntarily.
    log( "Shutting down event loop", Log::Debug );
    List< Connection >::Iterator it( d->connections );
    while ( it ) {
        Connection * c = it;
        ++it;
        try {
            Scope x( c->log() );
            if ( c->state() == Connection::Connected )
                c->react( Connection::Shutdown );
            if ( c->state() == Connection::Connected )
                c->write();
            if ( c->writeBuffer()->size() > 0 )
                c->log( "Still have " +
                        EString::humanNumber( c->writeBuffer()->size() ) +
                        " bytes to write", Log::Debug );
        } catch ( Exception e ) {
            // we don't really care at this point, do we?
        }
    }

    log( "Event loop stopped", Log::Debug );
}


/*! Dispatches events to the connection \a c, based on its current
    state, the time \a now and the results from select: \a r is true
    if the FD may be read, and \a w is true if we know that the FD may
    be written to. If \a now is past that Connection's timeout, we
    must send a Timeout event.
*/

void EventLoop::dispatch( Connection * c, bool r, bool w, uint now )
{
    int dummy1;
    socklen_t dummy2;
    dummy2 = sizeof(dummy1);
    if ( ::getsockopt( c->fd(), SOL_SOCKET, SO_RCVBUF,
                       &dummy1, &dummy2 ) < 0 ) {
        removeConnection( c );
        return;
    }

    try {
        Scope x( c->log() );
        if ( c->timeout() != 0 && now >= c->timeout() ) {
            c->setTimeout( 0 );
            c->react( Connection::Timeout );
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
            }
            else if ( error ) {
                c->react( Connection::Error );
                c->setState( Connection::Closing );
                r = false;
            }
        }

        if ( r ) {
            bool gone = false;
            if ( !c->hasProperty( Connection::Listens ) ) {
                int a = 0;
                int r = ioctl( c->fd(), FIONREAD, &a );
                if ( r >= 0 && a == 0 )
                    gone = true;
            }

            c->read();
            c->react( Connection::Read );

            if ( gone ) {
                c->setState( Connection::Closing );
                c->react( Connection::Close );
            }
        }

        uint s = c->writeBuffer()->size();
        c->write();
        // if we're closing anyway, and we can't write any of what we
        // want to write, then just forget the buffered data and go on
        // with the close
        if ( c->state() == Connection::Closing &&
             s && s == c->writeBuffer()->size() )
            c->writeBuffer()->remove( s );
    }
    catch ( Exception e ) {
        EString s;
        switch (e) {
        case Invariant:
            s = "Invariant failed";
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
        if ( !c->hasProperty( Connection::Listens ) )
            c->close();
    }

    if ( c->state() == Connection::Closing && !c->canWrite() )
        c->close();
    if ( !c->valid() )
        removeConnection( c );
}


/*! Instructs this EventLoop to perform an orderly shutdown in \a s
    seconds, by sending each participating Connection a Shutdown event
    before closing.

    Listener connections are closed right away, some/all external
    connections get a Shutdown event at once, everyone get a Shutdown
    event at final shutdown.
*/

void EventLoop::stop( uint s )
{
    if ( !s ) {
        d->stop = true;
        return;
    }

    (void)new LoopData::Stopper( s );
    List<Connection>::Iterator i( d->connections );
    while ( i ) {
        Connection * c = i;
        ++i;
        try {
            Scope x( c->log() );
            if ( c->hasProperty( Connection::Listens ) ) {
                c->react( Connection::Shutdown );
                c->close();
            }
            else if ( s <= 10 && !c->hasProperty( Connection::Internal ) ) {
                c->react( Connection::Shutdown );
            }
        } catch ( Exception e ) {
            removeConnection( c );
        }
    }
}


/*! Closes all Connections except \a c1 and \a c2. This helps TlsProxy
    do its work.
*/

void EventLoop::closeAllExcept( Connection * c1, Connection * c2 )
{
    List< Connection >::Iterator it( d->connections );
    while ( it ) {
        Connection * c = it;
        ++it;
        if ( c != c1 && c != c2 )
            c->close();
    }
}


/*! Closes all Connection except Listeners. When we fork, this allows
    us to keep the connections on one side of the fence.
*/

void EventLoop::closeAllExceptListeners()
{
    List< Connection >::Iterator it( d->connections );
    while ( it ) {
        Connection * c = it;
        ++it;
        if ( c->type() != Connection::Listener )
            c->close();
    }
}


/*! Flushes the write buffer of all connections. */

void EventLoop::flushAll()
{
    List< Connection >::Iterator it( d->connections );
    while ( it ) {
        Connection * c = it;
        ++it;
        c->write();
    }
}


/*! Returns true if this EventLoop is still attending to startup chores,
    and not yet processing Listener requests.
*/

bool EventLoop::inStartup() const
{
    return d->startup;
}


/*! Sets the startup state of this EventLoop to \a p. If \a p is true,
    then Listeners will not be processed until this function is called
    again with \a p set to false.
*/

void EventLoop::setStartup( bool p )
{
    d->startup = p;
}


/*! Returns true if this EventLoop is shutting down (ie. stop() has
    been called), and false if it's starting up or operating normally.
*/

bool EventLoop::inShutdown() const
{
    return d->stop;
}


/*! Returns a pointer to the global event loop, or 0 if setup() has not
    yet been called.
*/

EventLoop * EventLoop::global()
{
    return ::loop;
}


/*! This static function is just a convenient shorthand for calling
    stop() on the global() EventLoop.
*/

void EventLoop::shutdown()
{
    ::loop->stop();
}


/*! Records that \a t exists, so that the event loop will process \a
    t.
*/

void EventLoop::addTimer( Timer * t )
{
    d->timers.append( t );
}


/*! Forgets that \a t exists. The event loop will henceforth never
    call \a t.
*/

void EventLoop::removeTimer( Timer * t )
{
    List<Timer>::Iterator i( d->timers.find( t ) );
    if ( i )
        d->timers.take( i );
}

static GraphableNumber * imapgraph = 0;
static GraphableNumber * pop3graph = 0;
static GraphableNumber * smtpgraph = 0;
static GraphableNumber * othergraph = 0;
static GraphableNumber * internalgraph = 0;
static GraphableNumber * httpgraph = 0;
static GraphableNumber * dbgraph = 0;



/*! Scans the event loop and stores the current number of different
    connections using GraphableNumber.
*/

void EventLoop::setConnectionCounts()
{
    uint imap = 0;
    uint pop3 = 0;
    uint smtp = 0;
    uint other = 0;
    uint internal = 0;
    uint http = 0;
    uint db = 0;
    bool listeners = false;
    List<Connection>::Iterator c( d->connections );
    while ( c ) {
        switch( c->type() ) {
        case Connection::Client:
        case Connection::LogServer:
        case Connection::GraphDumper:
        case Connection::LogClient:
        case Connection::TlsProxy:
        case Connection::TlsClient:
        case Connection::RecorderClient:
        case Connection::RecorderServer:
        case Connection::Pipe:
            internal++;
            break;
        case Connection::DatabaseClient:
            db++;
            break;
        case Connection::ImapServer:
            imap++;
            break;
        case Connection::SmtpServer:
            smtp++;
            break;
        case Connection::SmtpClient:
        case Connection::ManageSieveServer:
        case Connection::EGDServer:
        case Connection::LdapRelay:
            other++;
            break;
        case Connection::Pop3Server:
            pop3++;
            break;
        case Connection::HttpServer:
            http++;
            break;
        case Connection::Listener:
            listeners = true;
            // we don't count these, we only count connections
            break;
        }
        ++c;
    }
    if ( !listeners )
        return;
    if ( !imapgraph ) {
        imapgraph = new GraphableNumber( "imap-connections" );
        pop3graph = new GraphableNumber( "pop3-connections" );
        smtpgraph = new GraphableNumber( "smtp-connections" );
        othergraph = new GraphableNumber( "other-connections" );
        internalgraph = new GraphableNumber( "internal-connections" );
        httpgraph = new GraphableNumber( "http-connections" );
        dbgraph = new GraphableNumber( "db-connections" );
    }
    imapgraph->setValue( imap );
    pop3graph->setValue( pop3 );
    smtpgraph->setValue( smtp );
    othergraph->setValue( other );
    internalgraph->setValue( internal );
    httpgraph->setValue( http );
    dbgraph->setValue( db );
}


/*! Stops all the SSL-enabled Listeners. */

void EventLoop::shutdownSSL()
{
    log( "Shutting down SSL-enabled Listeners", Log::Error );
    List< Connection >::Iterator it( d->connections );
    while ( it ) {
        Connection * c = it;
        ++it;
        if ( c->hasProperty( Connection::Listens ) &&
             c->hasProperty( Connection::StartsSSL ) )
            c->close();
    }
}


/*! Requests the event loop to collect garbage and clear any caches at
    the earliest opportunity. Used for debugging.
*/

void EventLoop::freeMemorySoon()
{
    ::freeMemorySoon = true;
}


/*! Instructs this event loop to collect garbage when memory usage
    passes \a limit bytes. The default is 0, which means to collect
    garbage even if very little is being used.
*/

void EventLoop::setMemoryUsage( uint limit )
{
    d->limit = limit;
}


/*! Returns whatever setMemoryUsage() has recorded, or 0 meaning to
    collect garbage often.
*/

uint EventLoop::memoryUsage() const
{
    return d->limit;
}
