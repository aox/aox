// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "http.h"

#include "link.h"
#include "httpsession.h"
#include "loop.h"
#include "page.h"
#include "codec.h"
#include "buffer.h"
#include "stringlist.h"
#include "configuration.h"


class HTTPData
{
public:
    HTTPData()
        : link( 0 ), session( 0 )
    {}

    HTTP::State state;
    bool sendContents;
    bool use11;
    bool connectionClose;
    String path;
    String error;
    StringList headers;
    StringList ignored;
    String referer;
    String page;
    uint contentLength;
    String body;

    Codec * preferredCodec;
    uint codecQuality;

    bool acceptsHtml;
    bool acceptsPng;
    bool acceptsLatin1;
    bool acceptsUtf8;
    bool acceptsIdentity;

    Link *link;
    HttpSession *session;

    struct HeaderListItem {
        HeaderListItem(): q( 0 ) {}

        String n;
        uint q; // q*100
    };
};


/*! \class HTTP http.h

    The HTTP class is a HTTP 1.1 server, with a number of umimportant
    deficiencies. It parses incoming requests almost according to the
    protocol rules and hands out simple answers. The main problem is
    that it doesn't handle conditions at all (so far) and that it
    doesn't handle exclusions (e.g. clients saying "I accept all
    formats except image/tiff").
*/


/*! Constructs an HTTP server for file descriptor \a s. */

HTTP::HTTP( int s )
    : Connection( s, Connection::HttpServer ), d( new HTTPData )
{
    clear();
    Loop::addConnection( this );
}


void HTTP::react( Event e )
{
    switch ( e ) {
    case Read:
        setTimeoutAfter( 1800 );
        parse();
        if ( d->state == Done ) {
            respond();
            enqueue( response()->join( "\r\n" ) );
            enqueue( "\r\n\r\n" );
            if ( d->sendContents )
                enqueue( d->page );

            if ( d->connectionClose )
                setState( Closing );

            clear();
        }
        break;

    case Timeout:
        log( "Idle timeout" );
        enqueue( "408 Timeout after 1800 seconds\r\n" );
        Connection::setState( Closing );
        break;

    case Connect:
    case Error:
    case Close:
        close();
        break;

    case Shutdown:
        enqueue( "505 Server must shut down\r\n" );
        break;
    }
}


/*! Parses incoming HTTP requests. This is a little simpler than the
    RFC says: We deviate in some of the ways
    http://www.and.org/texts/server-http.html describes.
*/

void HTTP::parse()
{
    if ( d->state == Request && canReadHTTPLine() )
        parseRequest( line().simplified() );
    while ( d->state == Header && canReadHTTPLine() )
        parseHeader( line() );
    if ( d->state == Body ) {
        if ( d->contentLength > 0 ) {
            Buffer *r = readBuffer();
            if ( r->size() < d->contentLength )
                return;
            d->body = r->string( d->contentLength );
            r->remove( d->contentLength );
        }
        d->state = Done;
    }
}


static uint inputLength( Buffer * r )
{
    uint i = 0;
    while ( i < r->size() &&
            ( (*r)[i] != '\n' ||
              ( (*r)[i] == '\n' &&
                ( (*r)[i+1] == '\t' || (*r)[i+1] == ' ' ) ) ) )
        i++;
    return i;
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

String HTTP::line()
{
    Buffer * r = readBuffer();
    uint i = inputLength( r );
    String l;
    if ( !i )
        return l;
    l = r->string( i );
    if ( l.endsWith( "\r" ) )
        l.truncate( l.length() - 1 );
    r->remove( i+1 ); // eat the LF too
    return l;
}



/*! Parses the original GET/HEAD request line \a l. */

void HTTP::parseRequest( String l )
{
    d->state = Header;
    int space = l.find( ' ' );
    if ( space < 0 ) {
        error( "400 Complete and utter parse error" );
        return;
    }

    String request = l.mid( 0, space );
    l = l.mid( space+1 );
    space = l.find( ' ' );
    if ( space < 0 ) {
        error( "400 Really total parse error" );
        return;
    }
    if ( request == "HEAD" ) {
        d->sendContents = false;
    }
    else if ( request == "GET" ) {
        d->sendContents = true;
    }
    else if ( request == "POST" ) {
        d->sendContents = true;
    }
    else {
        error( "405 Bad Request: " + request );
        addHeader( "Allow: GET, HEAD, POST" );
        return;
    }

    String path = l.mid( 0, space );
    l = l.mid( space+1 );

    // this is where String::stripWSP() would come in handy ;)
    space = l.find( ' ' );
    while ( space >= 0 ) {
        l = l.mid( 0, space ) + l.mid( space+1 );
        space = l.find( ' ' );
    }
    String protocol = l;

    if ( !protocol.startsWith( "HTTP/" ) ) {
        error( "400 Bad protocol: " + protocol + ". Only HTTP supported." );
        return;
    }
    bool ok = false;
    uint dot = 5;
    while ( dot < protocol.length() && protocol[dot] != '.' )
        dot++;
    if ( protocol[dot] != '.' ) {
        error( "400 Bad version number: " + protocol.mid( 6 ) );
        return;
    }
    uint major = protocol.mid( 5, dot-5 ).number( &ok );
    uint minor = 0;
    if ( ok )
        minor = protocol.mid( dot+1 ).number( &ok );
    if ( major != 1 ) {
        error( "400 Only HTTP/1.0 and 1.1 are supported" );
        return;
    }
    if ( minor > 0 )
        d->use11 = true;
    else
        d->connectionClose = true;
    // XXX: is this right? should we accept HTTP/1.2 and answer as
    // though it were 1.1?

    uint i = 0;
    while ( i < path.length() ) {
        if ( path[i] == '%' ) {
            bool ok = false;
            uint num = path.mid( i+1, 2 ).number( &ok, 16 );
            if ( !ok || path.length() < i + 3 ) {
                error( "400 Bad percent escape: " + path.mid( i, 3 ) );
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

    d->link = new Link( this, d->path );
    if ( !d->link->errorMessage().isEmpty() ) {
        addHeader( "X-Oryx-Debug: " + d->link->errorMessage() );
        error( "404 No such page: " + d->path );
        return;
    }
}


/*! Returns the HTTP parser's current state. The state changes after
    parsing a byte, so the return value is bound to next incoming
    byte, not the last one.
*/

HTTP::State HTTP::state() const
{
    return d->state;
}


/*! Parses a single HTTP header and stores its contents
    appropriately. May step on to the Done state.
*/

void HTTP::parseHeader( const String & h )
{
    if ( h.isEmpty() ) {
        d->state = Body;
        return;
    }

    uint i = h.find( ':' );
    if ( i < 1 ) {
        error( "400 Bad header: " + h.simplified() );
        return;
    }
    String n = h.mid( 0, i ).simplified().headerCased();
    String v = h.mid( i+1 ).simplified();

    if ( n == "Accept" ) {
        d->acceptsHtml = false;
        d->acceptsPng = false;
        parseList( n, v );
    }
    else if ( n == "Accept-Charset" ) {
        d->acceptsLatin1 = true; // XXX: wrong.
        d->acceptsUtf8 = false;
        parseList( n, v );
    }
    else if ( n == "Accept-Encoding" ) {
        parseList( n, v );
    }
    else if ( n == "Connection" ) {
        parseConnection( v );
    }
    else if ( n == "Cookie" ) {
        parseList( n, v );
    }
    else if ( n == "Expect" ) {
        error( "417 Expectations not supported" );
    }
    else if ( n == "Host" ) {
        parseHost( v );
    }
    else if ( n == "If-Match" ) {
        parseIfMatch( v );
    }
    else if ( n == "If-Modified-Since" ) {
        parseIfModifiedSince( v );
    }
    else if ( n == "If-None-Match" ) {
        parseIfNoneMatch( v );
    }
    else if ( n == "If-Unmodified-Since" ) {
        parseIfUnmodifiedSince( v );
    }
    else if ( n == "Referer" ) {
        parseReferer( v );
    }
    else if ( n == "Transfer-Encoding" ) {
        parseTransferEncoding( v );
    }
    else if ( n == "User-Agent" ) {
        parseUserAgent( v );
    }
    else if ( n == "Content-Length" ) {
        parseContentLength( v );
    }
    else {
        d->ignored.append( n );
    }
}


/*! Computes and returns a list containing the response line and its
    attendant headers. Each line does not have any trailing CRLF (or
    other whitespace).
*/

StringList * HTTP::response()
{
    return &d->headers;
}


/*! Responds to an already-parsed request.

*/

void HTTP::respond()
{
    addHeader( "Server: Mailstore/" +
               Configuration::compiledIn( Configuration::Version ) +
               " (http://www.oryx.com/mailstore/)" );

    Link l( this, d->path );
    addHeader( "Location: " + l.generate() );

    if ( !d->ignored.isEmpty() )
        addHeader( "X-Oryx-Ignored: " + d->ignored.join( ", " ) );
    d->ignored.clear();

    if ( d->error.isEmpty() ) {
        if ( !d->body.isEmpty() )
            d->page = d->body;
        else
            d->page = page();
        addHeader( "Content-Length: " + fn( d->page.length() ) );
        // probably want to add an etag header here. md5 the page and
        // that's it?
    }

    if ( d->session )
        addHeader( "Set-Cookie: session=\"" + d->session->key() + "\"" );

    if ( d->error.isEmpty() )
        d->headers.prepend( new String( "HTTP/1.0 200 OK" ) );
    else
        d->headers.prepend( new String( "HTTP/1.0 " + d->error ) );
}


/*! Records \a message as the error to be sent, unless another message
    has already been set. \a message must start with a three-digit
    error code.
*/

void HTTP::error( const String & message )
{
    if ( d->error.isEmpty() )
        d->error = message;
}


/*! Clears the object so it's ready to parse a new request. */

void HTTP::clear()
{
    d->error.truncate( 0 );
    d->state = Request;
}


/*! Parses \a type as an "Accept" header item with quality \a q. Not
    quite compliant, since we don't handle exclusions using
    wildcards. */

void HTTP::parseAccept( const String & type, uint q )
{
    int i = type.find( '/' );
    if ( i < 0 )
        i = type.length();
    String major = type.mid( 0, i ).simplified().lower();
    int j = type.find( ';', i+1 );
    if ( j < 0 )
        j = type.length();
    String minor = type.mid( i, j-i ).simplified().lower();
    if ( !q ) {
        // if q is 0, we ignore this type.
    }
    else if ( major == "*" ) {
        d->acceptsHtml = true;
        d->acceptsPng = true;
    }
    else if ( major == "text" ) {
        if ( minor == "*" || minor == "html" )
            d->acceptsHtml = true;
    }
    else if ( major == "image" ) {
        if ( minor == "*" || minor == "png" )
            d->acceptsPng = true;
    }
}


/*! Records \a cs as an "Accept-Charset" lite item with quality \a
    q. We're not compliant: We record whether we can send unicode, and
    look for a highest-quality other charset, that's it. We don't
    support things like "Accept-Encoding: *; q=0.8, utf-8; q=0" to
    mean anything except unicode.
*/

void HTTP::parseAcceptCharset( const String & cs, uint q )
{
    if ( cs == "*" && q ) {
        d->acceptsUtf8 = true;
        return;
    }
    Codec * c = Codec::byName( cs );
    if ( !c || q <= d->codecQuality )
        return;
    d->codecQuality = q;
    d->preferredCodec = c;
}


/*! Parses \a encoding as an "Accept-Encoding" lite item with quality
    \a q. As for Accept-Charset, we don't support exclusions.

    For now, only Identity is supported. Anyone wanting compression
    have to use TLS.
*/

void HTTP::parseAcceptEncoding( const String & encoding, uint q )
{
    if ( q && ( encoding == "identity" || encoding == "*" ) )
        d->acceptsIdentity = true;
}


/*! Parses the "Connection" header and records the parsed information. */

void HTTP::parseConnection( const String & v )
{
    String l = " " + v.lower() + " ";
    if ( v.find( " close " ) >= 0 )
        d->connectionClose = true;
}


/*! Parses the "Host" header and records the parsed information. */

void HTTP::parseHost( const String & v )
{
    if ( Configuration::toggle( Configuration::AcceptAnyHttpHost ) )
        return;
    String supplied = v.lower();
    if ( supplied.find( ':' ) >= 0 )
        supplied = supplied.mid( 0, supplied.find( ':' ) ).simplified();
    String correct = Configuration::text( Configuration::Hostname ).lower();
    if ( supplied == correct )
        return;
    error( "400 No such host: " + supplied +
           ". Only " + correct + " allowed" );
}


/*! Parses the "If-Match" header and records the parsed information. */

void HTTP::parseIfMatch( const String & )
{
    // later
}


/*! Parses the "If-Modified-Since" header and records the parsed
    information.
*/

void HTTP::parseIfModifiedSince( const String & )
{
    // later
}


/*! Parses the "If-None-Match" header and records the parsed information. */

void HTTP::parseIfNoneMatch( const String & )
{
    // later
}


/*! Parses the "If-Unmodified-Since" header and records the parsed
    information.
*/

void HTTP::parseIfUnmodifiedSince( const String & )
{
    // later
}


/*! Parses the "Referer" header and records the parsed information. */

void HTTP::parseReferer( const String & v )
{
    d->referer = v;
}


/*! Parses the "Transfer-Encoding" header and records the parsed
    information.
*/

void HTTP::parseTransferEncoding( const String & )
{

}


/*! Parses the "User-Agent" header and records the parsed information. */

void HTTP::parseUserAgent( const String & )
{
    // we ignore user-agent. thoroughly.
}


/*! Parses a single component of a Cookie header. */

void HTTP::parseCookie( const String &s )
{
    int eq = s.find( '=' );
    if ( eq > 0 ) {
        String name = s.mid( 0, eq ).stripWSP().lower();
        String value = s.mid( eq+1 ).stripWSP();

        if ( name == "session" )
            d->session = HttpSession::find( value.unquoted() );
    }
}


/*! Parses a Content-Length header. */

void HTTP::parseContentLength( const String &s )
{
    d->contentLength = s.number( 0 );
}


/*! Records \a s as a reply header to be sent. */

void HTTP::addHeader( const String & s )
{
    d->headers.append( s );
}


/*! Returns the page indicated by the current request. */

String HTTP::page()
{
    Page *page = new Page( d->link, this );
    return page->text();
}


/*! Parses \a value as a list header named \a name, and calls
    parseAccept() et al for each individual item.
*/

void HTTP::parseList( const String & name, const String & value )
{
    uint i = 0;
    while ( i < value.length() ) {
        uint start = i;
        while ( isTokenChar( value[i] ) )
            i++;
        String item = value.mid( start, i-start );
        uint q = 1000;
        skipValues( name, i, q );
        if ( i >= value.length() ) {
            parseListItem( name, item, q );
        }
        else if ( value[i] != ',' ) {
            error( "400 Expected comma at header " + name + " position " +
                   fn( i ) + ", saw " + value.mid( i ) );
            return;
        }
        else {
            i++;
            parseListItem( name, item, q );
        }
    }
}


/*! Parses the single list \a item as belonging to \a header. If
    there's a quality level, \a q represents the quality, if not, \a q
    is 1000.

*/

void HTTP::parseListItem( const String & header, const String & item, uint q )
{
    if ( header == "Accept" )
        parseAccept( item, q );
    else if ( header == "Accept-Charset" )
        parseAcceptCharset( item, q );
    else if ( header == "Cookie" )
        parseCookie( item );
}


/*! Skips past all arguments in \a value starting at \a i, moving \a i
    along. If one of the arguments is named q and has a legal value,
    \a q is changed.

    \a i is assumed to point to ';' on entry, and is left on ',' or at
    end of header on exit. If \a i already points to ',' or EOH,
    skipValues() is a noop.
*/

void HTTP::skipValues( const String & value, uint & i, uint & q )
{
    bool hasSeenQ = false;
    while ( true ) {
        while ( value[i] == ' ' )
            i++;
        if ( i >= value.length() || value[i] == ',' )
            return;
        expect( value, i, ';' );
        uint n = i;
        while ( isTokenChar( value[i] ) )
            i++;
        bool isQ = false;
        if ( value.mid( n, i-n ) == "q" && !hasSeenQ )
            isQ = true;
        expect( value, i, '=' );
        if ( value[i] == '"' ) {
            i++;
            while ( i < value.length() && value[i] != '"' ) {
                if ( value[i] == '\\' )
                    i++;
                i++;
            }
            expect( value, i, '"' );
            if ( isQ )
                error( "400 q cannot be quoted" );
        }
        else {
            n = i;
            if ( isQ ) {
                hasSeenQ = true;
                if ( value[i] >= '0' && value[i] <= '1' ) {
                    q = 1000 * ( value[i] - '0' );
                    i++;
                    if ( value[i] == '.' ) {
                        i++;
                        uint n = i;
                        while ( value[i] >= '0' && value[i] <= '9' )
                            i++;
                        String decimals = value.mid( n, i-n ) + "000";
                        bool ok;
                        q = q + decimals.mid( 0, 3 ).number( &ok );
                        if ( q > 1000 )
                            error( "400 Quality can be at most 1.000" );
                    }
                }
                else {
                    error( "400 Could not parse quality value: " +
                           value.mid( i ) );
                }
            }
            else {
                while ( isTokenChar( value[i] ) )
                    i++;
            }
        }
        while ( value[i] == ' ' )
            i++;
    }
}


/*! Checks that \a value has (optional) whitespace followed by \a c at
    position \a i, and reports an error if not. Advances \a i by one
    and skips past trailing whitespace.
*/

void HTTP::expect( const String & value, uint & i, char c )
{
    while ( value[i] == ' ' )
        i++;
    if ( value[i] != c ) {
        String e( "400 Expected '" );
        e.append( c );
        e.append( "' at position " +
                  fn( i ) +
                  ", saw " +
                  value.mid( i ) );
        error( e );
    }
    i++;
    while ( value[i] == ' ' )
        i++;
}


/*! Returns true if \a c is a HTTP/1.1 token char, and false if it is
    not. Notably, nulls aren't token chars.
*/

bool HTTP::isTokenChar( char c )
{
    if ( c < 32 || c > 126 )
        return false;
    if ( c == '(' | c == ')' | c == '<' | c == '>' | c == '@'
         | c == ',' | c == ';' | c == ':' | c == '\\' | c == '\''
         | c == '/' | c == '[' | c == ']' | c == '?' | c == '='
         | c == '{' | c == '}' | c == ' ' )
        return false;
    return true;
}


/*! Returns a pointer to the user associated with this server, or 0 if
    there is no such user. (For archive mailboxes, 0 is usually
    returned.)
*/

User *HTTP::user() const
{
    if ( d->session && !d->session->expired() )
        return d->session->user();
    return 0;
}


/*! Returns a pointer to the HttpSession object associated with this
    server, or 0 if no such session exists.
*/

HttpSession *HTTP::session() const
{
    return d->session;
}
