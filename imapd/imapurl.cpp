// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapurl.h"


class ImapUrlData
    : public Garbage
{
public:
    ImapUrlData()
        : valid( false ), i( 0 ), port( 143 ), uidvalidity( 0 ), uid( 0 )
    {}

    bool valid;

    uint i;
    String s;

    String user;
    String auth;
    String host;
    uint port;
    String mailbox;
    uint uidvalidity;
    uint uid;
    String section;
};


/*! \class ImapUrl imapurl.h
    A parser for the IMAP URL scheme described in RFC 2192.

    This class provides access to the components of an IMAP URL. It is
    meant for use by URLAUTH and CATENATE. Since those august extensions
    only permit URLs that refer to a message or part therein, this code
    does not recognise any of the less-specific forms at present.
*/

/*! Creates a new ImapUrl object to represent the URL \a s. */

ImapUrl::ImapUrl( const String & s )
    : d( new ImapUrlData )
{
    parse( s );
}


/*! Parses the string \a s as an IMAP URL, to extract its components and
    determine its validity. If it fails for any reason, valid() will be
    false afterwards. Called by the constructor.
*/

void ImapUrl::parse( const String & s )
{
    d->s = s;

    // imapurl = "imap://" [ iuserauth "@" ] hostport "/" icommand

    if ( !stepOver( "imap://" ) )
        return;

    // iuserauth = enc_user [iauth] / [enc_user] iauth

    int slash = d->s.find( '/', d->i );
    if ( slash < 0 )
        return;

    String iserver( d->s.mid( d->i, slash-d->i ) );
    if ( iserver.contains( "@" ) ) {
        d->user = xchars();
        if ( stepOver( ";AUTH=" ) )
            d->auth = xchars();
        else if ( d->user.isEmpty() )
            return;

        if ( !stepOver( "@" ) )
            return;
    }

    if ( !hostport() )
        return;

    if ( !stepOver( "/" ) )
        return;

    // icommand = enc_mailbox [uidvalidity] iuid [isection]

    d->mailbox = xchars( true );
    if ( d->mailbox.isEmpty() )
        return;

    if ( stepOver( ";uidvalidity=" ) )
        if ( !number( &d->uidvalidity ) )
            return;

    if ( !stepOver( "/;uid=" ) || !number( &d->uid ) )
        return;

    if ( stepOver( "/;section=" ) ) {
        d->section = xchars( true );
        if ( d->section.isEmpty() )
            return;
    }

    d->valid = true;
}


/*! Returns true if the URL given to the constructor is syntactically
    valid, and false otherwise.
*/

bool ImapUrl::valid() const
{
    return d->valid;
}


/*! If \a s occurs (irrespective of case) at the current position in the
    URL we're parsing, this function updates the current position to the
    first character after its occurrence and returns true. Otherwise, it
    returns false without affecting the current position.
*/

bool ImapUrl::stepOver( const String & s )
{
    if ( d->s.mid( d->i, s.length() ).lower() == s.lower() ) {
        d->i += s.length();
        return true;
    }

    return false;
}


/*! Returns true only if \a c is acceptable to the unreserved production
    in RFC 1738, and false otherwise.
*/

bool ImapUrl::unreserved( char c )
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

bool ImapUrl::escape( char * c )
{
    if ( d->s[d->i] == '%' ) {
        bool ok;
        uint p = d->s.mid( d->i+1, 2 ).number( &ok, 16 );
        if ( ok ) {
            d->i += 2;
            *c = (char)p;
            return true;
        }
    }

    return false;
}


/*! If a valid IMAP nz-number occurs at the current position in the URL,
    this function sets the uint pointed to by \a n to its value, changes
    the current position to point past the number, and returns true. If
    no valid number occurs, the function returns false without altering
    the current position (though it may alter what \a n points to).
*/

bool ImapUrl::number( uint * n )
{
    uint j = d->i;

    if ( d->s[j] == '0' )
        return false;
    while ( j < d->s.length() &&
            ( d->s[j] >= '0' && d->s[j] <= '9' ) )
        j++;

    bool ok;
    *n = d->s.mid( d->i, j-d->i ).number( &ok );
    if ( ok && *n != 0 ) {
        d->i = j;
        return true;
    }

    return false;
}


/*! Steps over and returns a (possibly empty) sequence of characters at
    the current position in this URL. If \a b is false, which it is by
    default, characters matching achar are accepted; if \a b is true,
    characters matching bchar are accepted instead.
*/

String ImapUrl::xchars( bool b )
{
    String s;

    while ( d->i < d->s.length() ) {
        char c = d->s[d->i];

        if ( unreserved( c ) || ( c == '&' || c == '=' || c == '~' ) ||
             ( b && ( c == ':' || c == '@' || c == '/' ) ) ||
             escape( &c ) )
        {
            // We won't eat the beginning of "/;UID".
            if ( b && c == '/' && d->s[d->i+1] == ';' )
                break;
            s.append( c );
        }
        else {
            break;
        }

        d->i++;
    }

    return s;
}


/*! Parses and steps over an RFC 1738 hostport production at the current
    position in the URL we're parsing. Returns true if it encountered a
    valid hostport, and false otherwise.
*/

bool ImapUrl::hostport()
{
    // We're very laid-back about parsing the "host" production. About
    // the only thing we'll reject is -foo.com, and not doing so would
    // make the loop below twice as simple.

    char c = d->s[d->i];
    while ( ( (c|0x20) >= 'a' && (c|0x20) <= 'z' ) ||
            ( c >= '0' && c <= '9' ) )
    {
        d->host.append( c );
        d->i++;

        c = d->s[d->i];
        while ( ( (c|0x20) >= 'a' && (c|0x20) <= 'z' ) ||
                ( c >= '0' && c <= '9' ) ||
                ( c == '-' ) )
        {
            d->host.append( c );
            d->i++;

            c = d->s[d->i];
        }

        if ( c == '.' ) {
            d->host.append( c );
            d->i++;
            c = d->s[d->i];
        }
    }

    if ( d->host.isEmpty() )
        return false;

    if ( d->s[d->i] == ':' ) {
        d->i++;
        if ( !number( &d->port ) )
            return false;
    }

    return true;
}
