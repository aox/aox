// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "http.h"

#include "dict.h"
#include "handler.h"
#include "buffer.h"
#include "eventloop.h"
#include "configuration.h"
#include "estringlist.h"
#include "scope.h"
#include "log.h"


class HTTPData
    : public Garbage
{
public:
    HTTPData()
        : state( HTTP::Request ),
          status( 200 ),
          use11( false ), sendContents( true ), connectionClose( true ),
          haveLength( false ), handled( false ), contentLength( 0 ),
          requestLog( 0 )
    {}

    HTTP::State state;

    uint status;
    EString method;
    EString message;
    EString hostSupplied;

    bool use11;
    bool sendContents;
    bool connectionClose;
    bool haveLength;
    bool handled;

    EString body;
    EString path;
    EStringList headers;
    Dict<EString> received;
    uint contentLength;

    Log * requestLog;
};


/*! \class HTTP http.h

    The HTTP class is the protocol layer of an HTTP/1.1 server, and
    nothing else: it reads a request, parses the request line and the
    headers, collects the body, and offers a way to send a response.

    There's no Accept, Accept-Charset or Accept-Encoding parsing, no
    cookies, no sessions and no form parameters.  Conditional requests
    (If-Match and friends) are not implemented, as they were not
    before, and chunked request bodies are rejected rather than
    misunderstood.
*/


/*! Constructs an HTTP server for file descriptor \a s. */

HTTP::HTTP( int s )
    : Connection( s, Connection::HttpServer ), d( new HTTPData )
{
    clear();
    EventLoop::global()->addConnection( this );
    setTimeoutAfter( 1800 );
}


void HTTP::react( Event e )
{
    switch ( e ) {
    case Read:
        parse();
        break;

    case Timeout:
        log( "Idle timeout" );
        Connection::setState( Closing );
        break;

    case Connect:
    case Error:
    case Close:
        break;

    case Shutdown:
        setStatus( 503, "Server shutting down" );
        respond( "text/plain", "The server is shutting down.\n" );
        break;
    }
}


/*! Reads as much of the request as has arrived, and once it is
    complete, hands it to handle(). A request we could not parse is
    answered here instead, since a subclass cannot do anything useful
    with one.
*/

void HTTP::parse()
{
    if ( d->state == Request ) {
        if ( canReadHTTPLine() )
            parseRequest( line().simplified() );
    }

    Scope s;
    if ( d->requestLog )
        s.setLog( d->requestLog );

    while ( d->state == Header && canReadHTTPLine() )
        parseHeader( line() );

    if ( d->state == Body ) {
        Buffer * r = readBuffer();
        if ( d->contentLength <= r->size() ) {
            if ( d->contentLength ) {
                d->body = r->string( d->contentLength );
                r->remove( d->contentLength );
                ::log( "Received request body of " + fn( d->contentLength ) +
                       " bytes for " + d->method, Log::Debug );
            }
            d->state = Parsed;
        }
    }

    if ( d->state != Parsed )
        return;

    // handle() may answer later, so it must be called only once per
    // request: more input, or a timeout, brings us back here while the
    // answer is still being prepared.
    if ( d->handled )
        return;
    d->handled = true;

    if ( d->status != 200 )
        respond( "text/plain", d->message + "\n" );
    else
        handle();
}


/*! Answers the parsed request, by handing it to whichever
    HttpHandler serves the path, or with 404 if none does.
*/

void HTTP::handle()
{
    HttpHandler * h = HttpHandler::find( d->path );
    if ( h ) {
        h->handle( this );
        return;
    }

    setStatus( 404, "No such URL: " + d->path );
    respond( "text/plain", d->message + "\n" );
}


/*! Sends \a response as a response of type \a type. */

void HTTP::respond( const EString & type, const EString & response )
{
    EString srv( "Server: Archiveopteryx/" );
    srv.append( Configuration::compiledIn( Configuration::Version ) );
    srv.append( " (http://www.archiveopteryx.org)" );

    addHeader( srv );
    addHeader( "Content-Length: " + fn( response.length() ) );
    addHeader( "Content-Type: " + type );

    if ( d->connectionClose )
        addHeader( "Connection: close" );

    if ( d->use11 )
        enqueue( "HTTP/1.1 " );
    else
        enqueue( "HTTP/1.0 " );

    enqueue( fn( d->status ) + " " + d->message + "\r\n" );
    enqueue( d->headers.join( "\r\n" ) );
    enqueue( "\r\n\r\n" );

    if ( d->sendContents ) {
        enqueue( response );
        write();
    }

    ::log( "Sent " + (fn( d->status ) + "/" + d->message).quoted() +
           " response of " + fn( response.length() ) + " bytes." );

    d->requestLog = 0;

    if ( d->connectionClose ) {
        setState( Closing );
        log( "Closing connection" );
    }
    else {
        log( "Keeping connection alive for 1800 more seconds." );
        setTimeoutAfter( 1800 );
    }

    clear();
}


/*! Returns the HTTP parser's current state. The state changes after
    parsing a byte, so the return value is bound to next incoming
    byte, not the last one.
*/

HTTP::State HTTP::state() const
{
    return d->state;
}


/*! Returns the request method, e.g. "GET", or an empty string if the
    request line has not been parsed yet.
*/

EString HTTP::method() const
{
    return d->method;
}


/*! Returns the requested path, with any percent escapes decoded. */

EString HTTP::path() const
{
    return d->path;
}


/*! Returns a string containing the request body, if any was supplied
    with the request, and an empty string if none was.
*/

EString HTTP::body() const
{
    return d->body;
}


/*! Returns the value of the received header \a name, or an empty
    string if the request did not contain it. \a name is matched
    case-insensitively, as HTTP requires, so header( "authorization" )
    and header( "Authorization" ) are the same question.
*/

EString HTTP::header( const EString & name ) const
{
    EString * v = d->received.find( name.headerCased() );
    if ( v )
        return *v;
    EString empty;
    return empty;
}


/*! Returns true if this connection is encrypted, so that a caller
    can decide whether a password may cross it.
*/

bool HTTP::encrypted() const
{
    return hasTls();
}


/*! Returns the status code that the next response will use. */

uint HTTP::status() const
{
    return d->status;
}


static uint inputLength( Buffer * r )
{
    uint i = 0;
    while ( i < r->size() &&
            ( (*r)[i] != '\n' ||
              ( (*r)[i] == '\n' &&
                ( (*r)[i+1] == '\t' || (*r)[i+1] == ' ' ) ) ) )
        i++;
    if ( i < r->size() )
        return i;
    return UINT_MAX;
}


/*! Returns true if the readBuffer() contains a complete HTTP/1.1
    request or header line, taking account of escaped line feeds.
*/

bool HTTP::canReadHTTPLine() const
{
    Buffer * r = readBuffer();
    uint i = inputLength( r );
    if ( i < r->size() )
        return true;
    return false;
}


/*! Reads, removes and returns a line, including escaped line
    feeds. The trailing LF or CRLF is removed from the input stream,
    but not returned.
*/

EString HTTP::line()
{
    Buffer * r = readBuffer();
    uint i = inputLength( r );
    EString l;
    if ( i >= r->size() )
        return l;
    l = r->string( i );
    if ( l.endsWith( "\r" ) )
        l.truncate( l.length() - 1 );
    r->remove( i+1 ); // eat the LF too
    return l;
}


/*! Parses the request line \a l. */

void HTTP::parseRequest( const EString & l )
{
    setTimeoutAfter( 1800 );
    d->state = Header;
    Scope s( Connection::log() );
    d->requestLog = new Log;
    s.setLog( d->requestLog );
    ::log( "Request: " + l, Log::Debug );

    // Request-Line = Method SP Request-URI SP HTTP-Version CRLF

    int space = l.find( ' ' );
    if ( space < 0 ) {
        setStatus( 400, "Complete and utter parse error" );
        return;
    }

    EString request = l.mid( 0, space );
    EString rest = l.mid( space+1 );
    space = rest.find( ' ' );
    if ( space < 0 ) {
        setStatus( 400, "Really total parse error" );
        return;
    }

    d->method = request;
    if ( request == "HEAD" ) {
        d->sendContents = false;
    }
    else if ( request == "GET" || request == "POST" ) {
        d->sendContents = true;
    }
    else {
        setStatus( 405, "Bad Request: " + request );
        addHeader( "Allow: GET, HEAD, POST" );
        return;
    }

    EString path = rest.mid( 0, space );
    rest = rest.mid( space+1 );

    // Thanks to our friend LWS, HTTP-Version might say " 1   .     1"
    // when it means "1.1".

    EString protocol = rest.simplified();
    protocol.replace( " ", "" );

    if ( !protocol.startsWith( "HTTP/" ) ) {
        setStatus( 400, "Bad protocol: " + protocol + ". "
                        "Only HTTP supported." );
        return;
    }

    bool ok = false;
    uint dot = 5;
    while ( dot < protocol.length() && protocol[dot] != '.' )
        dot++;
    if ( protocol[dot] != '.' ) {
        setStatus( 400, "Bad version number: " + protocol.mid( 6 ) );
        return;
    }
    uint major = protocol.mid( 5, dot-5 ).number( &ok );
    uint minor = 0;
    if ( ok )
        minor = protocol.mid( dot+1 ).number( &ok );
    if ( major != 1 ) {
        setStatus( 400, "Only HTTP/1.0 and 1.1 are supported" );
        return;
    }
    if ( minor > 0 ) {
        d->use11 = true;
        d->connectionClose = false;
    }

    uint i = 0;
    d->path.truncate( 0 );
    while ( i < path.length() ) {
        if ( path[i] == '%' ) {
            bool ok = false;
            uint num = path.mid( i+1, 2 ).number( &ok, 16 );
            if ( !ok || path.length() < i + 3 ) {
                setStatus( 400, "Bad percent escape: " + path.mid( i, 3 ) );
                return;
            }
            d->path.append( (char)num );
            i += 3;
        }
        else {
            d->path.append( path[i] );
            i++;
        }
    }

    ::log( "Received: " + d->method + " " + d->path + " " + protocol );
}


/*! Parses a single HTTP header in the EString \a h and stores its
    contents appropriately. May step on to the Body state.
*/

void HTTP::parseHeader( const EString & h )
{
    if ( h.isEmpty() ) {
        d->state = Body;
        if ( !d->haveLength && d->method == "POST" )
            setStatus( 411, "POST needs a Content-Length" );
        return;
    }

    uint i = h.find( ':' );
    if ( i < 1 ) {
        setStatus( 400, "Bad header: " + h.simplified() );
        return;
    }
    EString n = h.mid( 0, i ).simplified().headerCased();
    EString v = h.mid( i+1 ).simplified();

    ::log( "Received: " + n.quoted() + " = " + v.quoted(), Log::Debug );

    // Later headers of the same name win, which is wrong for the ones
    // that may be repeated, and those are ones we do not read.
    d->received.insert( n, new EString( v ) );

    if ( n == "Connection" ) {
        if ( v.lower() == "close" )
            d->connectionClose = true;
        else if ( v.lower() == "keep-alive" && d->use11 )
            d->connectionClose = false;
    }
    else if ( n == "Host" ) {
        parseHost( v );
    }
    else if ( n == "Expect" ) {
        setStatus( 417, "Expectations not supported" );
    }
    else if ( n == "Transfer-Encoding" ) {
        // We would have to dechunk the body to read it, and silently
        // reading the wrong bytes is worse than saying no.
        if ( v.lower() != "identity" )
            setStatus( 501, "Transfer-Encoding not supported: " + v );
    }
    else if ( n == "Content-Length" ) {
        bool ok = false;
        uint l = v.number( &ok );
        if ( !ok ) {
            setStatus( 400, "Bad Content-Length: " + v );
            return;
        }
        d->haveLength = true;
        d->contentLength = l;
    }
}


/*! Parses the "Host" header \a v and records the parsed information.
*/

void HTTP::parseHost( const EString & v )
{
    d->hostSupplied = v.lower();
    if ( d->hostSupplied.endsWith( "." ) )
        d->hostSupplied.truncate( d->hostSupplied.length() - 1 );
    uint i = 0;
    uint c = d->hostSupplied.length();
    while ( i < d->hostSupplied.length() ) {
        bool bad = false;
        if ( d->hostSupplied[i] == '.' ) {
            if ( i == 0 || i == d->hostSupplied.length() - 1 )
                bad = true;
            if ( d->hostSupplied[i+1] == '.' )
                bad = true;
        }
        else if ( d->hostSupplied[i] == ':' ) {
            if ( i == 0 || i == d->hostSupplied.length() - 1 )
                bad = true;
            c = i;
        }
        else if ( d->hostSupplied[i] == '[' ) {
            if ( i > 0 )
                bad = true;
        }
        else if ( d->hostSupplied[i] == ']' ) {
            if ( i < d->hostSupplied.length() - 1 )
                bad = true;
        }
        else if ( ( d->hostSupplied[i] >= 'a' && d->hostSupplied[i] <= 'z' ) ||
                  ( d->hostSupplied[i] >= '0' && d->hostSupplied[i] <= '9' ) ||
                  d->hostSupplied[i] == '/' ||
                  d->hostSupplied[i] == '-' ) {
            // ok
        }
        else {
            bad = true;
        }
        if ( bad ) {
            setStatus( 400, "Bad Host header: " + d->hostSupplied );
            return;
        }
        i++;
    }
    if ( c < d->hostSupplied.length() ) {
        bool ok = false;
        uint port = d->hostSupplied.mid( c + 1 ).number( &ok );
        if ( ok && port == self().port() )
            d->hostSupplied.truncate( c );
    }

    if ( Configuration::toggle( Configuration::AcceptAnyHttpHost ) )
        return;

    EString correct = Configuration::text( Configuration::Hostname ).lower();
    if ( d->hostSupplied == correct )
        return;
    setStatus( 400, "No such host: " + d->hostSupplied +
               ". Only " + correct + " allowed" );
}


/*! Returns the value of the Host header, lowercased but otherwise
    unchanged.
*/

EString HTTP::hostHeader() const
{
    return d->hostSupplied;
}


/*! Records \a status and \a message as the status line to be sent,
    unless another non-200 message has already been set.
*/

void HTTP::setStatus( uint status, const EString & message )
{
    if ( d->status && d->status != status )
        ::log( "Status changed to " + fn( status ) + "/" + message );
    if ( d->status == 200 ) {
        d->status = status;
        d->message = message;
        d->state = Parsed;
    }
}


/*! Adds \a s to the list of headers to be sent with the next
    response. \a s is a complete header line, without the trailing
    CRLF.
*/

void HTTP::addHeader( const EString & s )
{
    d->headers.append( s );
}


/*! Clears the object so it's ready to parse a new request. */

void HTTP::clear()
{
    d->body.truncate( 0 );
    d->method.truncate( 0 );
    d->state = Request;
    d->haveLength = false;
    d->handled = false;
    d->contentLength = 0;
    d->status = 200;
    d->message = "OK";
    d->sendContents = true;
    d->headers.clear();
    d->received.clear();
}


/*! \class HTTPS http.h
    This class inherits from HTTP and starts TLS at once.
*/

/*! Constructs an HTTPS server on fd \a s. */

HTTPS::HTTPS( int s )
    : HTTP( s )
{
    startTls();
}
