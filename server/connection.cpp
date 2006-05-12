// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "connection.h"

#include "buffer.h"
#include "endpoint.h"
#include "string.h"
#include "scope.h"
#include "eventloop.h"
#include "log.h"
#include "byteforwarder.h"
#include "tls.h"
#include "file.h"

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
          state( Connection::Invalid ),
          type( Connection::Client ),
          tls( false ), pending( false ),
          l( 0 )
    {}

    int fd;
    uint timeout;
    Buffer *r, *w;
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
    d->l = new Log( Log::General );
}


/*! Creates an Inactive \a type connection using \a fd. */

Connection::Connection( int fd, Type type )
    : d( new ConnectionData )
{
    d->l = new Log( Log::General );
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

    if ( st == Connected  )
        log( "Connected: " + description(), Log::Debug );
    else if ( st == Closing )
        log( "Closing: " + description(), Log::Debug );
    d->state = st;
}


/*! Returns the current state of the connection. */

Connection::State Connection::state() const
{
    return d->state;
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
    switch ( type ) {
    case ImapServer:
        d->l->setFacility( Log::IMAP );
        break;
    case SmtpServer:
        d->l->setFacility( Log::SMTP );
        break;
    case DatabaseClient:
        d->l->setFacility( Log::Database );
        break;
    default:
        break;
    }
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

String Connection::description() const
{
    String r;
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
    case OryxServer:
        r = "Oryx administrative server";
        break;
    case OryxClient:
        r = "Oryx administrative connection";
        break;
    case OryxConsole:
        r = "Administrative console";
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
    case Listener:
        r = "Listener";
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
        if ( d->type == Client ||
             d->type == LogClient ||
             d->type == DatabaseClient )
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

    if ( !d->self.valid() ) {
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

    if ( !d->peer.valid() ) {
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
    if ( valid() )
        d->w->write( d->fd );
}


/*! Returns true unless we have encountered an EOF while reading from
    our peer.
*/

bool Connection::canRead()
{
    return !d->r->eof() && d->r->error() == 0;
}


/*! Returns true if we have any data to send. */

bool Connection::canWrite()
{
    return d->w->size() > 0 && d->w->error() == 0;
}


/*! Returns true only if the Event \a e is pending on this Connection.
*/

bool Connection::isPending( Event e )
{
    return ( d->pending && d->event == e );
}


/*! Appends \a s to this Connection's writeBuffer().
*/

void Connection::enqueue( const String &s )
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
            String data = readBuffer()->string( n );
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
    if ( d->tls )
        return;

    write();

    EventLoop::global()->removeConnection( this );
    EventLoop::global()->removeConnection( s->serverSide() );
    EventLoop::global()->removeConnection( s->userSide() );

    ByteForwarder * b1 = new ByteForwarder( d->fd );
    ByteForwarder * b2 = new ByteForwarder( s->userSide()->fd() );
    d->fd = s->serverSide()->fd();

    b1->setState( state() );
    b2->setState( s->userSide()->state() );
    setState( s->serverSide()->state() );

    b1->setSibling( b2 );

    s->userSide()->d->fd = -1;
    s->serverSide()->d->fd = -1;

    EventLoop::global()->addConnection( b1 );
    EventLoop::global()->addConnection( b2 );
    EventLoop::global()->addConnection( this );

    log( "Negotiating TLS for client " + b1->peer().string(),
         Log::Debug );

    d->tls = true;
}


/*! Returns true if TLS has been or is being negotiated for this
    connection, and false if ne
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

    (Why does this return an int instead of a bool?)
*/

int Connection::listen( const Endpoint &e )
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
            log( "Cannot listen to " +
                 e.address() + " port " + fn( e.port() ) +
                 " because another process is occupying it", Log::Error );
            return -1;
        }
        log( "bind( " + fn( d->fd ) + ", " +
             e.address() + " port " + fn( e.port() ) +
             " ) returned errno " + fn( errno ), Log::Debug );
        return -1;
    }
    if ( ::listen( d->fd, 64 ) < 0 ) {
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

void Connection::log( const String &m, Log::Severity s )
{
    d->l->log( m, s );
}


/*! Commits all pending log messages of severity \a s or greater.
*/

void Connection::commit( Log::Severity s )
{
    d->l->commit( s );
}


