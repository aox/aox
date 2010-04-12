// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "connection.h"

#include "tlsthread.h"

#include "log.h"
#include "file.h"
#include "user.h"
#include "scope.h"
#include "query.h"
#include "buffer.h"
#include "estring.h"
#include "endpoint.h"
#include "eventloop.h"
#include "allocator.h"
#include "resolver.h"
#include "user.h"

// errno
#include <errno.h>
// close
#include <unistd.h>
// fcntl, F_GETFL, F_SETFL, O_NDELAY
#include <fcntl.h>
// sockaddr_in, sockaddr_in6, IPPROTO_TCP
#include <netinet/in.h>
#include <sys/socket.h>
// time
#include <time.h>


class ConnectionData
    : public Garbage
{
public:
    ConnectionData()
        : fd( -1 ), timeout( 0 ), r( 0 ), w( 0 ),
          wbt( 0 ), wbs( 0 ),
          state( Connection::Invalid ),
          type( Connection::Client ),
          tls( false ), pending( false ),
          l( 0 )
    {}

    int fd;
    uint timeout;
    Buffer *r, *w;
    uint wbt, wbs;
    Connection::State state;

    Connection::Type type;
    bool tls;
    bool pending;
    Endpoint self, peer;
    Connection::Event event;
    Log *l;
};


/*! \class Connection connection.h
    Represents a single TCP connection (or other socket).

    This class contains code that is shared between different types of
    connections, including the Listener (which accepts connections and
    creates new Connection objects) and the IMAP server class.

    A connection knows about its state(), type(), socket fd(), next
    timeout(), and its self() and peer() endpoints (if applicable). It
    also has a readBuffer() and a writeBuffer(). There is a
    description() that returns a text string describing the
    connection.

    The react() function is the main interface between the Loop and each
    Connection object. It must be implemented by subclasses, and is used
    to tell the object about Connection::Events that have occurred (Read,
    Timeout, etc.).
*/

/*! Creates an Invalid connection with no associated FD.
*/

Connection::Connection()
    : d( new ConnectionData )
{
    d->l = new Log;
}


/*! Creates an Inactive \a type connection using \a fd. */

Connection::Connection( int fd, Type type )
    : d( new ConnectionData )
{
    d->l = new Log;
    setType( type );
    init( fd );
}


/*! This private function associates a Connection with an \a fd and sets
    its state to Inactive. It does nothing if the connection is already
    valid, or if \a fd is negative.
*/

void Connection::init( int fd )
{
    if ( d->state != Invalid || fd < 0 )
        return;

    d->fd = fd;
    d->state = Inactive;
    d->timeout = 0;
    d->r = new Buffer;
    d->w = new Buffer;
    setBlocking( false );
}


/*! Closes this connection. The object remains mostly valid, as GC is
    expected to do the memory deallocation. */

Connection::~Connection()
{
    close();
}


/*! Sets the connection state to \a st, which must be one of the
    following states:

    Invalid: No valid FD (just created or closed).

    Inactive: Valid, but unused FD.

    Listening: Valid FD in SYN_RECV.

    Connecting: Valid FD in SYN_SENT.

    Connected: Connected FD.

    Closing: Connected FD, but will be closed (and revert to Invalid)
    once the write buffers have been flushed.
*/

void Connection::setState( Connection::State st )
{
    if ( st == d->state )
        return;

    Scope x( log() );
    bool internal = hasProperty( Internal );
    if ( st == Connected  )
        log( "Connected: " + description() + " (" +
             fn( EventLoop::global()->connections()->count() ) + " connections)",
             internal ? Log::Debug : Log::Significant );
    else if ( st == Invalid && ( d->state == Closing || d->state == Connected ) )
        log( "Closing: " + description() + " (" +
             fn( EventLoop::global()->connections()->count() ) + " connections)",
             internal ? Log::Debug : Log::Info );
    d->state = st;
}


/*! Returns the current state of the connection. */

Connection::State Connection::state() const
{
    return d->state;
}


/*! Returns true if this Connection has \a p. The return value based
    on type() and self().
*/

bool Connection::hasProperty( Property p ) const
{
    bool ssl = false;
    if ( p == StartsSSL ) {
        uint port = self().port();
        if ( port == Configuration::scalar( Configuration::ImapsPort ) ||
             port == Configuration::scalar( Configuration::SmtpsPort ) ||
             port == Configuration::scalar( Configuration::HttpsPort ) )
            ssl = true;
    }

    switch ( type() ) {
    case Client:
        if ( p == Internal )
            return true;
        break;
    case DatabaseClient:
    case LogServer:
    case LogClient:
    case TlsClient:
    case RecorderClient:
    case RecorderServer:
    case GraphDumper:
    case EGDServer:
        if ( p == Internal )
            return true;
        break;

    case Pipe:
        if ( p == Internal )
            return true;
        if ( p == StartsSSL && ssl )
            return true;
        break;

    case TlsProxy:
        if ( p == Internal )
            return true;
        if ( p == StartsSSL )
            return true;
        break;

    case ImapServer:
    case SmtpServer:
    case HttpServer:
        if ( p == StartsSSL && ssl )
            return true;
        break;

    case Connection::LdapRelay:
    case SmtpClient:
        break;

    case Listener:
        if ( p == Listens )
            return true;
        if ( p == StartsSSL && ssl )
            return true;
        break;

    case Pop3Server:
    case ManageSieveServer:
        break;
    }

    return false;
}


/*! Returns true if this Connection object is valid and usable, and
    false if not. In practice, false means that its socket is bad.
    Short for state() != Connection::Invalid.
*/

bool Connection::valid() const
{
    return d->state != Invalid;
}


/*! Returns true if this connection is in active use, and false if it
    is not.
*/

bool Connection::active() const
{
    return ( d->state != Invalid && d->state != Inactive );
}


/*! Returns the FD associated with a connection, or a negative number if
    the connection is invalid. */

int Connection::fd() const
{
    if ( !valid() )
        return -1;
    return d->fd;
}


/*! Notifies this Connection that it really is of \a type, contrary to
    whatever it may earlier have believed. It also correctly sets the
    Log facility used by this connection.

    This function is for use by classes (e.g. Listener, Database) that
    use the default Connection constructor, but don't want its default
    connection type of "Client".
*/

void Connection::setType( Type type )
{
    d->type = type;
}


/*! Returns the Type of this Connection, as set using the constructor. */

Connection::Type Connection::type() const
{
    return d->type;
}


/*! Returns a single-line text string describing this connection. The
    string is intended for debugging.

    Subclasses may reimplement this if this implementation is
    insufficient.
*/

EString Connection::description() const
{
    EString r;
    switch( d->type ) {
    case Client:
        r = "Client";
        break;
    case DatabaseClient:
        r = "Database client";
        break;
    case ImapServer:
        r = "IMAP server";
        break;
    case LogServer:
        r = "Log server";
        break;
    case LogClient:
        r = "Log client";
        break;
    case GraphDumper:
        r = "Administrative server";
        break;
    case SmtpServer:
        r = "SMTP server";
        break;
    case SmtpClient:
        r = "SMTP client";
        break;
    case Pop3Server:
        r = "POP3 server";
        break;
    case HttpServer:
        r = "HTTP server";
        break;
    case TlsProxy:
        r = "TLS proxy";
        break;
    case TlsClient:
        r = "TLS client";
        break;
    case RecorderClient:
        r = "TCP stream recorder client";
        break;
    case RecorderServer:
        r = "TCP stream recorder";
        break;
    case EGDServer:
        r = "EGD server";
        break;
    case Listener:
        r = "Listener";
        break;
    case Connection::LdapRelay:
        r = "LDAP relay";
        break;
    case Pipe:
        r = "Byte forwarder";
        break;
    case ManageSieveServer:
        r = "ManageSieve server";
        break;
    }
    Endpoint her = peer();
    Endpoint me = self();

    if ( me.valid() )
        r.append( " " + me.string() );

    if ( her.valid() ) {
        r.append( " connected to " );
        if ( d->type == Client || d->type == LogClient ||
             d->type == TlsClient || d->type == SmtpClient ||
             d->type == DatabaseClient || d->type == RecorderClient )
            r.append( "server " );
        else
            r.append( "client " );
        r.append( her.string() );
    }

    if ( d->fd >= 0 )
        r = r + ", on fd " + fn( d->fd );
    else
        r = "Invalid " + r;

    return r;
}


/*! Returns the time (in seconds since the epoch) at or after which this
    connection expects to receive a Timeout event. The default value of
    0 means that the connection does not want Timeout events.
*/

uint Connection::timeout() const
{
    return d->timeout;
}


/*! Sets the connection timeout to \a tm seconds from the epoch. */

void Connection::setTimeout( uint tm )
{
    d->timeout = tm;
}


/*! Sets the connection timeout to \a n seconds from the current time.
*/

void Connection::setTimeoutAfter( uint n )
{
    d->timeout = n + (uint)time(0);
}


/*! Extends the existing timeout() by \a n seconds.
    Does nothing if no timeout is set.
*/

void Connection::extendTimeout( uint n )
{
    if ( d->timeout != 0 )
        d->timeout += n;
}


/*! Makes the connection non-blocking if \a block is false, or blocking
    if it is true.
*/

void Connection::setBlocking( bool block )
{
    if ( !valid() )
        return;

    int flags = fcntl( d->fd, F_GETFL, 0 );
    if ( flags < 0 )
        die( FD );

    if ( !block )
        flags = flags | O_NDELAY;
    else
        flags = flags & ~O_NDELAY;

    if ( fcntl( d->fd, F_SETFL, flags ) < 0 )
        die( FD );
}


/*! Returns a pointer to the connection's read buffer. */

Buffer *Connection::readBuffer() const
{
    return d->r;
}


/*! Returns a pointer to the connection's write buffer. */

Buffer *Connection::writeBuffer() const
{
    return d->w;
}


static union {
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
} sa;


/*! Returns an Endpoint representing the local end of the connection,
    or an invalid Endpoint if something goes wrong (for example, if
    the connection is inactive).
*/

Endpoint Connection::self() const
{
    socklen_t n = sizeof( sa );

    if ( valid() && !d->self.valid() ) {
        if ( ::getsockname( d->fd, (sockaddr *)&sa, &n ) >= 0 )
            d->self = Endpoint( (sockaddr *)&sa );
    }

    return d->self;
}


/*! Returns an Endpoint representing the remote end of the connection,
    an invalid Endpoint if something goes wrong (for example, if the
    connection is inactive).
*/

Endpoint Connection::peer() const
{
    socklen_t n = sizeof( sa );

    if ( valid() && !d->peer.valid() ) {
        if ( ::getpeername( d->fd, (sockaddr *)&sa, &n ) >= 0 )
            d->peer = Endpoint( (sockaddr *)&sa );
    }

    return d->peer;
}


/*! Closes this connection. */

void Connection::close()
{
    if ( valid() && d->fd >= 0 )
        ::close( d->fd );
    setState( Invalid );
    EventLoop::global()->removeConnection( this );
}


/*! Reads waiting input from the connected socket. Does nothing in
    case the Connection isn't valid(). */

void Connection::read()
{
    if ( valid() )
        d->r->read( d->fd );
}


/*! Writes pending output to the connected socket. Does nothing in
    case the Connection isn't valid(). */

void Connection::write()
{
    if ( !valid() )
        return;

    d->w->write( d->fd );
    uint wbs = d->w->size();
    if ( wbs && !d->wbs ) {
        d->wbt = time( 0 );
        d->wbs = wbs;
        if ( d->wbs > 16384 )
            log( "Have to queue " +
                 EString::humanNumber( d->wbs ) + " output bytes " );
    }
    else if ( d->wbs && !wbs ) {
        uint now = time( 0 );
        if ( now > d->wbt + 1 ) {
            log( "Wrote " +
                 EString::humanNumber( d->wbs ) +
                 " bytes to client in " + fn( now - d->wbt ) +
                 " seconds" );
        }
        d->wbt = 0;
        d->wbs = 0;
    }
}


/*! Returns true if we have any data to send. */

bool Connection::canWrite()
{
    return d->w->size() > 0;
}


/*! Returns true only if the Event \a e is pending on this Connection.
*/

bool Connection::isPending( Event e )
{
    return ( d->pending && d->event == e );
}


/*! Appends \a s to this Connection's writeBuffer().
*/

void Connection::enqueue( const EString &s )
{
    writeBuffer()->append( s );
}


/*! \fn void Connection::react( Event event )

    Subclasses are required to define this method to react appropriately
    to \a event notifications from the main loop.
*/


class Halfpipe : public Connection {
private:
    Halfpipe *partner;

public:
    Halfpipe( int fd )
        : Connection( fd, Connection::Pipe ), partner( 0 )
    {
        EventLoop::global()->addConnection( this );
    }

    ~Halfpipe()
    {
        EventLoop::global()->removeConnection( this );
    }

    void connect( Halfpipe *b ) {
        partner = b;
        b->partner = this;
        b->setState( Connected );
        setState( Connected );
    }

    void react( Event e ) {
        if ( e == Read ) {
            uint n = readBuffer()->size();
            EString data = readBuffer()->string( n );
            partner->enqueue( data );
            partner->write();
            readBuffer()->remove( n );
        }
        else if ( e == Close ) {
            partner->setState( Closing );
        }
    }
};


/*! Starts TLS negotiation using \a s on this connection. */

void Connection::startTls( TlsServer * s )
{
    if ( d->tls || !valid() )
        return;

    write();

    log( "Negotiating TLS for client " + peer().string(),
         Log::Debug );

    int sv[2];
    int r = ::socketpair( AF_UNIX, SOCK_STREAM, 0, sv );
    if ( r < 0 ) {
        log( "Cannot create more FDs", Log::Error );
        // there's nothing much to do, we just have to close the
        // connection and hope the situation passes.
        close();
        return;
    }

    TlsThread * t = new TlsThread();
    if ( t->broken() ) {
        log( "Cannot create more threads", Log::Error );
        close();
        ::close( sv[0] );
        ::close( sv[1] );
        return;
    }
    Allocator::addEternal( t, "another TLS thread" );

    int flags = fcntl( sv[0], F_GETFL, 0 );
    if ( flags < 0 )
        die( FD );
    flags = flags | O_NDELAY;
    if ( fcntl( sv[0], F_SETFL, flags ) < 0 )
        die( FD );
    if ( fcntl( sv[1], F_SETFL, flags ) < 0 )
        die( FD );

    t->setClientFD( d->fd );
    t->setServerFD( sv[0] );
    d->fd = sv[1];

    if ( s )
        log( "Note: TlsServer was created and need not be", Log::Debug );

    d->tls = true;
}


/*! Returns true if TLS has been or is being negotiated for this
    connection, and false if not.
*/

bool Connection::hasTls() const
{
    return d->tls;
}


/*! Listens to the specified endpoint \a e. If the operation succeeds,
    the connection enters the Listening state. If not, -1 is returned,
    and the connection state is unchanged.

    If the connection is not valid, a socket is created and associated
    with it first.

    Logs errors only if \a silent is false.

    (Why does this return an int instead of a bool?)
*/

int Connection::listen( const Endpoint &e, bool silent )
{
    if ( !e.valid() )
        return -1;

    if ( !valid() ) {
        init( socket( e.protocol() ) );
        if ( !valid() )
            return -1;
    }

    int i = 1;
    ::setsockopt( d->fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof (int) );

    if ( e.protocol() == Endpoint::Unix )
        unlink( File::chrooted( e.address() ).cstr() );

    int retcode = ::bind( d->fd, e.sockaddr(), e.sockaddrSize() );
    if ( retcode < 0 ) {
        if ( errno == EADDRINUSE ) {
            if ( !silent )
                log( "Cannot listen to " +
                     e.address() + " port " + fn( e.port() ) +
                     " because another process is occupying it", Log::Error );
            return -1;
        }
        if ( !silent )
            log( "bind( " + fn( d->fd ) + ", " +
                 e.address() + " port " + fn( e.port() ) +
                 " ) returned errno " + fn( errno ), Log::Debug );
        return -1;
    }
    if ( ::listen( d->fd, 64 ) < 0 ) {
        if ( !silent )
            log( "listen( " + fn( d->fd ) + ", 64 ) for address " +
                 e.address() + " port " + fn( e.port() ) +
                 " ) returned errno " + fn( errno ), Log::Debug );
        return -1;
    }

    setState( Listening );
    d->self = e;
    return 1;
}


/*! Connects to the specified endpoint \a e. If the operation succeeds,
    the connection enters one of the Connected or Connecting states (in
    the latter case, the connection should expect one of the Connect or
    Error events). Returns -1 on error.

    If the connection is not valid, a socket is created and associated
    with it first.
*/

int Connection::connect( const Endpoint &e )
{
    if ( !e.valid() )
        return -1;

    if ( !valid() ) {
        init( socket( e.protocol() ) );
        if ( !valid() )
            return -1;
    }

    int n = ::connect( d->fd, e.sockaddr(), e.sockaddrSize() );

    d->pending = false;
    setState( Connecting );
    if ( n == 0 || ( n < 0 && errno == EINPROGRESS ) ) {
        if ( n == 0 ) {
            d->event = Connect;
            d->pending = true;
        }
        n = 1;
    }
    else {
        d->event = Error;
        d->pending = true;
        n = -1;
    }

    return n;
}


/*! Accepts a queued connection from a listening socket, and returns the
    newly created FD, or -1 on error. Should only be called on Listening
    connections.
*/

int Connection::accept()
{
    if ( state() != Listening )
        return -1;

    socklen_t len = 0;
    struct sockaddr_storage l;

    int s = ::accept( fd(), (sockaddr *)&l, &len );
    return s;
}


/*! Returns a new TCP socket for the protocol \a p, or -1 on error. */

int Connection::socket( Endpoint::Protocol p )
{
    int sock = -1;

    switch ( p ) {
    case Endpoint::Unix:
        sock = ::socket( AF_UNIX, SOCK_STREAM, 0 );
        break;
    case Endpoint::IPv4:
        sock = ::socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
        break;
    case Endpoint::IPv6:
        sock = ::socket( AF_INET6, SOCK_STREAM, IPPROTO_TCP );
        break;
    }

    return sock;
}


/*! Returns the Log used by this Connection. This is never a null pointer.
*/

Log * Connection::log() const
{
    return d->l;
}


/*! Logs the message \a m with severity \a s using this Connection's Log
    object.
*/

void Connection::log( const EString &m, Log::Severity s )
{
    d->l->log( m, s );
}


static bool sixDoesFour;


/*! Records whether listening to :: ("any ipv6 address") also listens
    to 0.0.0.0 ("any ipv4 address"). Listener calls it with \a e true
    if that is the case, and stops trying.

*/

void Connection::setAny6ListensTo4( bool e )
{
    ::sixDoesFour = e;
}


/*! Returns what setAny6ListensTo4() set, or false initially. */

bool Connection::any6ListensTo4()
{
    return ::sixDoesFour;
}


/*! Returns true if this Connection can access mail, and false if not.
    Bases its decision on the allow-plaintext-access configuration
    variable.
*/

bool Connection::accessPermitted() const
{
    EString x;
    x = Configuration::text( Configuration::AllowPlaintextAccess );
    x = x.lower();

    if ( x == "always" )
        return true;

    if ( x == "localhost" && self().address() == peer().address() )
        return true;

    if ( hasTls() )
        return true;

    return false;
}


class SerialConnector
    : public Connection
{
private:
    Connection * host;
    List<SerialConnector> * connectors;
    Endpoint target;
    uint timeouts;

public:
    // Every SerialConnector gets a pointer to the host connection, the
    // List it belongs to, and the Endpoint to which it should connect.
    // This constructor doesn't do anything. The real work begins in
    // connect() below.

    SerialConnector( Connection * c, List<SerialConnector> * l, Endpoint e )
        : host( c ), connectors( l ), target( e ), timeouts( 0 )
    {
    }

    // The caller sets up the List of connectors, and calls connect() on
    // the first one, which tries to connect to its target Endpoint. If
    // that fails right away, it yields to the next connector. Otherwise
    // it waits for the EventLoop to call react() to decide what to do.

    void connect()
    {
        log( "Trying " + target.string(), Log::Debug );

        if ( Connection::connect( target ) < 0 ) {
            next( true );
            return;
        }

        setTimeoutAfter( 1 );
        EventLoop::global()->addConnection( this );
    }

    void react( Event e )
    {
        // If we've succeeded in making a connection, we can kill all of
        // the other connectors and substitute ourselves for the parent
        // connection.

        if ( e == Connect ) {
            List<SerialConnector>::Iterator it( connectors );
            while ( it ) {
                SerialConnector * sc = it;
                if ( sc != this ) {
                    EventLoop::global()->removeConnection( sc );
                    sc->close();
                }
                ++it;
            }
            substitute( host, Connect );
            host->setState( Connecting );
        }

        // If there's an Error, we know we won't be able to connect, so
        // we remove ourselves from the List of connectors and connect()
        // the next one in line. If the initial 1-second timeout expires
        // we extend the timeout and yield without removing ourselves,
        // since the connection attempt may yet succeed.

        else if ( e == Error || e == Timeout ) {
            if ( e == Timeout ) {
                setTimeoutAfter( 10 );
                timeouts++;
            }

            next( e == Error || timeouts > 1 );
        }

        else {
            // XXX: If the EventLoop starts forwarding Read etc. to us,
            // we're deeply screwed.
        }
    }

    // This function is responsible for removing the current connector
    // from the list, if necessary, and then calling connect() on the
    // next one in line, which is the first one that is neither broken
    // nor Connecting. It needs to deal with the awful possibility that
    // no connectors are left to try (i.e. they all failed).

    void next( bool remove )
    {
        List<SerialConnector>::Iterator it( connectors );

        if ( remove ) {
            while ( it ) {
                if ( it == this )
                    connectors->take( it );
                else
                    ++it;
            }
            it = connectors;
        }

        uint alive = 0;
        while ( it ) {
            SerialConnector * sc = it;
            if ( sc->state() != Connecting ) {
                alive++;
                sc->connect();
                break;
            }
            ++it;
        }

        if ( alive == 0 && connectors->isEmpty() ) {
            Endpoint e( "0.0.0.0", 0 );
            init( socket( e.protocol() ) );
            substitute( host, Error );
            host->setState( Connecting );
        }
    }
};


/*! \overload
    This form of connect() takes an \a address (e.g. "localhost") and
    \a port instead of an Endpoint. It tries to resolve that address
    to a list of connection targets; and tries to connect to each of
    those in turn. The first successful connection is used, and the
    caller is notified by the EventLoop as usual. It can use peer()
    to find out which address we actually connected to.

    If \a address resolves to only one thing (e.g. it is an IP address
    already, or a Unix-domain socket, or a hostname that maps to only
    one address), this function just calls the usual form of connect()
    on the result.

    Returns -1 on failure (i.e. the name could not be resolved to any
    valid connection targets), and 0 on (temporary) success.

    This function disregards RFC 3484 completely, and instead issues
    many (partially concurrent) TCP connections. We think many
    concurrent connections is better than serial ordered approach 3484
    prescribes, but combining the two approaches would be even better
    (ie. order as 3484 says, but issue connection as we do).
*/

int Connection::connect( const EString & address, uint port )
{
    EStringList names( Resolver::resolve( address ) );
    if ( names.count() == 1 )
        return connect( Endpoint( address, port ) );

    List<SerialConnector> * l = new List<SerialConnector>;

    EStringList::Iterator it( names );
    while ( it ) {
        EString name( *it );
        Endpoint e( name, port );
        if ( e.valid() )
            l->append( new SerialConnector( this, l, e ) );
        ++it;
    }

    if ( l->count() == 0 )
        return -1;

    l->first()->connect();
    return 0;
}


/*! This very evil function exists to help a SerialConnector (above) to
    substitute itself for another connection \a other, which called the
    two-argument form of connect(). This function should not be called
    by anyone else, and nobody should wonder what \a event is.
*/

void Connection::substitute( Connection * other, Event event )
{
    EventLoop::global()->removeConnection( this );
    setTimeoutAfter( 10 );
    d->type = other->d->type;
    d->l = other->d->l;
    other->d = d;
    other->d->pending = true;
    other->d->event = event;
    EventLoop::global()->addConnection( other );
}
