// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapurl.h"

#include "imap.h"
#include "mailbox.h"
#include "imapsession.h"
#include "imapparser.h"
#include "date.h"
#include "user.h"


class ImapUrlParser
    : public ImapParser
{
public:
    ImapUrlParser( const String &s )
        : ImapParser( s )
    {}

    bool hasIuserauth();
    bool unreserved( char );
    bool escape( char * );
    String xchars( bool = false );
    bool hostport( String &, uint * );
    bool hasUid();
    Date * isoTimestamp();
    String urlauth();
};


class ImapUrlData
    : public Garbage
{
public:
    ImapUrlData()
        : valid( false ), isRump( false ), rumpEnd( 0 ), imap( 0 ),
          user( 0 ), port( 143 ), uidvalidity( 0 ), uid( 0 ),
          expires( 0 )
    {}

    bool valid;
    bool isRump;
    uint rumpEnd;

    const IMAP * imap;

    User * user;
    String auth;
    String host;
    uint port;
    String mailbox;
    uint uidvalidity;
    uint uid;
    String section;
    Date * expires;
    String access;
    String mechanism;
    String urlauth;

    String orig;
    String text;
};


/*! \class ImapUrl imapurl.h
    A parser for the IMAP URL scheme described in RFC 2192.

    This class provides access to the components of an IMAP URL. It is
    meant for use by URLAUTH and CATENATE. Since those august extensions
    only permit URLs that refer to a message or part therein, this code
    does not recognise any of the less-specific forms at present. Both
    absolute and relative URLs are supported.
*/

/*! Creates a new ImapUrl object to represent the IMAP URL \a s. The URL
    must be absolute (i.e., begin with "imap://").
*/

ImapUrl::ImapUrl( const String & s )
    : d( new ImapUrlData )
{
    parse( s );
}


/*! Creates a new ImapUrl object to represent the IMAP URL \a s. The URL
    must be relative, and is interpreted in the context of the specified
    \a imap object. If a session has not been established, the URL must
    specify a mailbox; but otherwise, the currently-selected mailbox is
    used as a part of the base.

    This behaviour is intended to serve the needs of CATENATE.
*/

ImapUrl::ImapUrl( const IMAP * imap, const String & s )
    : d( new ImapUrlData )
{
    d->imap = imap;
    parse( s );
}


/*! Parses the string \a s as an IMAP URL, to extract its components and
    determine its validity. If it fails for any reason, valid() will be
    false afterwards. Called by the constructor.
*/

void ImapUrl::parse( const String & s )
{
    d->orig = s;
    ImapUrlParser * p = new ImapUrlParser( s );

    // imapurl = "imap://" iserver "/" icommand

    if ( !d->imap ) {
        if ( !p->present( "imap://" ) )
            return;

        // iserver = [ iuserauth "@" ] hostport
        // iuserauth = enc_user [iauth] / [enc_user] iauth

        if ( p->hasIuserauth() ) {
            d->user = new User;
            d->user->setLogin( p->xchars() );
            if ( p->present( ";AUTH=" ) )
                d->auth = p->xchars();
            else if ( d->user->login().isEmpty() )
                return;
            if ( !p->present( "@" ) )
                return;
        }

        if ( !p->hostport( d->host, &d->port ) )
            return;

        if ( !p->present( "/" ) )
            return;
    }

    // icommand = enc_mailbox [uidvalidity] iuid [isection]

    if ( !( d->imap && d->imap->session() ) || !p->hasUid() ) {
        d->mailbox = p->xchars( true );
        if ( d->mailbox.isEmpty() )
            return;

        if ( p->present( ";uidvalidity=" ) ) {
            d->uidvalidity = p->nzNumber();
            if ( !p->ok() )
                return;
        }
    }

    p->require( "/;uid=" );
    d->uid = p->number();

    if ( p->present( "/;section=" ) )
        d->section = p->xchars( true );

    // RFC 4467 additions:
    // [ ";EXPIRE=" date-time ] ";URLAUTH=" access ":" mechanism ":" urlauth
    // (These clauses apply only to absolute URLs.)

    if ( !d->imap ) {
        if ( p->nextChar() == ';' ) {
            if ( p->present( ";expire=" ) )
                d->expires = p->isoTimestamp();
            p->require( ";urlauth=" );
            if ( p->present( "submit+" ) )
                d->access = "submit+" + p->xchars();
            else if ( p->present( "user+" ) )
                d->access = "user+" + p->xchars();
            else if ( p->present( "authuser" ) )
                d->access = "authuser";
            else if ( p->present( "anonymous" ) )
                d->access = "anonymous";
            else
                return;
            d->rumpEnd = p->pos();
            if ( p->present( ":" ) ) {
                p->require( "internal" );
                p->require( ":" );
                d->urlauth = p->urlauth();
                d->mechanism = "internal";
            }
            else {
                d->isRump = true;
            }
        }
    }

    p->end();
    if ( !p->ok() )
        return;

    d->valid = true;
}


/*! Returns true if the URL given to the constructor is syntactically
    valid, and false otherwise.
*/

bool ImapUrl::valid() const
{
    return d->valid;
}


/*! Returns true if this URL is an "authimapurlrump", i.e. it specifies
    ";URLAUTH=access", but does not include a mechanism name or URLAUTH
    token. Returns false otherwise, including for URLs that are invalid.
*/

bool ImapUrl::isRump() const
{
    return d->isRump;
}


/*! Returns the unmodified original input passed to the ImapUrl
    constructor, without regard to whether the URL is valid() or
    not.
*/

String ImapUrl::orig() const
{
    return d->orig;
}


/*! Returns only the rump of this URL (see RFC 4467), or an empty string
    if the rump is not meaningfully defined.
*/

String ImapUrl::rump() const
{
    return d->orig.mid( 0, d->rumpEnd );
}


/*! Returns a pointer to the User object representing the user specified
    in the "iuserauth" portion of this URL, or 0 if none was specified.
    For relative URLs, which are interpreted with reference to a given
    IMAP object, this function returns the current IMAP user.
*/

User * ImapUrl::user() const
{
    if ( d->imap )
        return d->imap->user();
    return d->user;
}


/*! Returns the "AUTH" specification from this URL, or an empty string
    if none was specified.
*/

String ImapUrl::auth() const
{
    return d->auth;
}


/*! Returns the hostname from this URL. (This function makes no
    allowance for relative URLs, because it's not needed yet.)
*/

String ImapUrl::host() const
{
    return d->host;
}


/*! Returns the port number specified in this URL. */

uint ImapUrl::port() const
{
    return d->port;
}


/*! Returns the name of the mailbox from this URL. The mailbox is either
    specified explicitly in the URL, or, if an IMAP session exists, and
    no mailbox has been specified, from the currently selected mailbox.
*/

String ImapUrl::mailboxName() const
{
    if ( d->mailbox.isEmpty() &&
         d->imap && d->imap->session() )
        return d->imap->session()->mailbox()->name();
    return d->mailbox;
}


/*! Returns the mailbox UIDVALIDITY specified in this URL. */

uint ImapUrl::uidvalidity() const
{
    return d->uidvalidity;
}


/*! Returns the message UID specified in this URL. */

uint ImapUrl::uid() const
{
    return d->uid;
}


/*! Returns the message section part specified in this URL, or an empty
    string if no section was specified (in which case the URL refers to
    an entire message).
*/

String ImapUrl::section() const
{
    return d->section;
}


/*! Returns a pointer to a Date representing the specified expiry date
    for this URL, or 0 if no EXPIRE=date-time was specified.
*/

Date * ImapUrl::expires() const
{
    return d->expires;
}


/*! Returns the "access" part of the URLAUTH specified for this URL, or
    an empty string if none was specified.
*/

String ImapUrl::access() const
{
    return d->access.lower();
}


/*! Returns the name of the authorization mechanism specified for this
    URL, or an empty string if no URLAUTH was specified.
*/

String ImapUrl::mechanism() const
{
    return d->mechanism;
}


/*! Returns the URLAUTH token specified for this URL, or an empty string
    if no URLAUTH was specified.
*/

String ImapUrl::urlauth() const
{
    return d->urlauth;
}


/*! This function, meant for use by the ImapUrlFetcher, sets the text()
    for this URL to \a s.
*/

void ImapUrl::setText( const String &s )
{
    d->text = s;
}


/*! Returns the text that this URL refers to, as retrieved and set by an
    ImapUrlFetcher, or an empty string if setText() has not been called.
*/

String ImapUrl::text() const
{
    return d->text;
}


/*! \class ImapUrlParser imapurl.cpp
    Provides functions used to parse RFC 2192 productions.

    This class inherits from ImapParser, is used internally by ImapUrl
    to parse various components of an IMAP URL as defined in RFC 2192,
    which relies on the IMAP grammar in RFC 2060 (hence the derivation
    from ImapParser).
*/


/*! This function returns true if an (optional) iuserauth component is
    present in the iserver specification. It expects the cursor to be
    just after the "//" following the scheme on entry, and leaves its
    position unchanged.
*/

bool ImapUrlParser::hasIuserauth()
{
    int slash = str.find( '/', at );
    if ( slash < 0 )
        return false;
    return str.mid( at, slash-at ).contains( "@" );
}


/*! Returns true only if \a c is acceptable to the unreserved production
    in RFC 1738, and false otherwise.
*/

bool ImapUrlParser::unreserved( char c )
{
    return ( ( c >= 'a' && c <= 'z' ) || ( c >= 'A' && c <= 'Z' ) ||
             ( c >= '0' && c <= '9' ) ||
             ( c == '$' || c == '-' || c == '_' || c == '.' || c == '+' ) ||
             ( c == '!' || c == '*' || c == ',' || c == '(' || c == ')' ||
               c == '\'' ) );
}


/*! If a %xx escape occurs at the current position in this URL, this
    function sets the character pointed to by \a c to the value of the
    escaped character, steps past the escape sequence, and returns true.
    Otherwise it returns false without affecting either the position or
    whatever \a c points to.
*/

bool ImapUrlParser::escape( char * c )
{
    if ( nextChar() == '%' ) {
        bool ok;
        uint p = str.mid( at+1, 2 ).number( &ok, 16 );
        if ( ok ) {
            step( 3 );
            *c = (char)p;
            return true;
        }
    }

    return false;
}


/*! Steps over and returns a (possibly empty) sequence of characters at
    the current position in this URL. If \a b is false, which it is by
    default, characters matching achar are accepted; if \a b is true,
    characters matching bchar are accepted instead.
*/

String ImapUrlParser::xchars( bool b )
{
    String s;

    char c = nextChar();
    while ( c != '\0' ) {
        if ( unreserved( c ) || ( c == '&' || c == '=' || c == '~' ) ||
             ( b && ( c == ':' || c == '@' || c == '/' ) ) )
        {
            // Nasty hack: we won't eat the beginning of "/;UID".
            if ( b && c == '/' && str[at+1] == ';' )
                break;

            s.append( c );
            step();
        }
        else if ( c == '%' && escape( &c ) ) {
            s.append( c );
        }
        else {
            break;
        }

        c = nextChar();
    }

    return s;
}


/*! Parses and steps over an RFC 1738 hostport production at the current
    position in the URL we're parsing. Returns true if it encountered a
    valid hostport, and false otherwise. Stores the extracted values in
    \a host and \a port.
*/

bool ImapUrlParser::hostport( String & host, uint * port )
{
    // We're very laid-back about parsing the "host" production. About
    // the only thing we'll reject is -foo.com, and not doing so would
    // make the loop below twice as simple.

    char c = nextChar();
    while ( ( (c|0x20) >= 'a' && (c|0x20) <= 'z' ) ||
            ( c >= '0' && c <= '9' ) )
    {
        host.append( c );
        step();

        c = nextChar();
        while ( ( (c|0x20) >= 'a' && (c|0x20) <= 'z' ) ||
                ( c >= '0' && c <= '9' ) ||
                ( c == '-' ) )
        {
            host.append( c );
            step();
            c = nextChar();
        }

        if ( c == '.' ) {
            host.append( c );
            step();
            c = nextChar();
        }
    }

    if ( host.isEmpty() )
        return false;

    *port = 143;
    if ( nextChar() == ':' ) {
        step();
        *port = nzNumber();
        if ( !ok() )
            return false;
    }

    return true;
}


/*! Returns true only if the cursor points to "/;uid=", and false
    otherwise. It does not affect the position of the cursor in
    either case.
*/

bool ImapUrlParser::hasUid()
{
    return ( str.mid( at, at+6 ).lower() == "/;uid=" );
}


/*! Extracts an RFC 3339 format date-time string, advances the cursor
    past its end, and returns a pointer to a Date representing it. It
    is an error if no valid date-time is found, and 0 is returned.
*/

Date * ImapUrlParser::isoTimestamp()
{
    bool ok;
    uint year = digits( 4, 4 ).number( &ok );
    require( "-" );
    uint month = digits( 2, 2 ).number( &ok );
    require( "-" );
    uint day = digits( 2, 2 ).number( &ok );
    require( "t" );
    uint hours = digits( 2, 2 ).number( &ok );
    require( ":" );
    uint minutes = digits( 2, 2 ).number( &ok );
    require( ":" );
    uint seconds = digits( 2, 2 ).number( &ok );
    if ( present( "." ) )
        number();

    int zone = 1;
    if ( present( "z" ) )
        zone = 0;
    else if ( present( "-" ) )
        zone = -1;
    else if ( !present( "+" ) )
        setError( "Time zone must be z, or start with - or +" );
    zone = zone * ( ( 60 * digits( 2, 2 ).number( &ok ) ) +
                    digits( 2, 2 ).number( &ok ) );

    Date * d = new Date;
    d->setDate( year, month, day, hours, minutes, seconds, zone );
    if ( !ok || !d->valid() ) {
        setError( "Invalid date specified" );
        return 0;
    }

    return d;
}


/*! Extracts and returns a sequence of at least 32 hexadecimal digits,
    advancing the cursor past its end. It is an error if fewer than 32
    digits are available at the cursor.
*/

String ImapUrlParser::urlauth()
{
    String s;

    char c = nextChar();
    while ( ( c >= '0' && c <= '9' ) ||
            ( c >= 'a' && c <= 'f' ) ||
            ( c >= 'A' && c <= 'F' ) )
    {
        step();
        s.append( c );
        c = nextChar();
    }

    if ( s.length() < 32 )
        setError( "Expected at least 32 hex digits, but saw only " +
                  fn( s.length() ) );

    return s;
}
