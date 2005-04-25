#include "link.h"

#include "http.h"
#include "user.h"
#include "page.h"
#include "mailbox.h"
#include "message.h"


class LinkData
{
public:
    LinkData()
        : type( Link::Error ),
          mailbox( 0 ), uid( 0 )
        {}
    String s;
    Link::Type type;
    Mailbox * mailbox;
    uint uid;
    String error;
};


/*! \class Link page.h

    The Link class is the basic Oryx web page class. It decides what
    needs to be done based on URL path components and tells a Page to
    do it, or makes a path based on other data.
*/


/*! Constructs an empty Link. */

Link::Link()
    : d( new LinkData )
{
}


/*! Constructs and parses a link with path \a s.
*/

Link::Link( const String &s )
    : d( new LinkData )
{
    parse( s );
}


/*! Parses \a s as a http path. \a s must begin with a slash and
    cannot contain any escape sequences.
*/

void Link::parse( const String & s )
{
    d->s = s;

    String prefix = removePrefix();

    if ( prefix == "archive" ) {
        d->type = ArchiveMailbox;
        parseMailbox();
        parseUid();
    }
    else if ( prefix == "folder" ) {
        d->type = WebmailMailbox;
        parseMailbox();
        parseUid();
    }
    else if ( prefix == "" ) {
        d->type = Webmail;
    }
    else {
        error( "Garbage at end of URL: " + s );
    }
}


/*! Generates a path that represents this Link object.
*/

String Link::string() const
{
    String s;
    switch( d->type ) {
    case ArchiveMailbox:
        s = "/archive/" + fn( d->mailbox->id() );
        break;
    case WebmailMailbox:
        s = "/folder/" + fn( d->mailbox->id() );
        break;
    case Webmail:
        s = "/webmail";
        break;
    case ArchiveMessage:
        s = "/archive/" + fn( d->mailbox->id() ) + "/" + fn( d->uid );
        break;
    case WebmailMessage:
        s = "/folder/" + fn( d->mailbox->id() ) + "/" + fn( d->uid );
        break;
    case Error:
        break;
    }
    return s;
}


/*! Parses a UID. It skips an optional prefix /. */

void Link::parseUid()
{
    if ( d->s[0] != '/' )
        return;
    uint i = 1;
    while ( d->s[i] >= '0' && d->s[i] <= '9' )
        i++;
    if ( i > 0 ) {
        bool ok = false;
        d->uid =  d->s.mid( 1, i-1 ).number( &ok );
        if ( ok ) {
            if ( d->type == ArchiveMailbox )
                d->type = ArchiveMessage;
            else if ( d->type == WebmailMailbox )
                d->type = WebmailMessage;
            d->s = d->s.mid( i );
        }
    }
}


/*! Removes and returns the component of this link between the first
    pair of slashes.

    (Should this function be named nextWord? We'll see.)
*/

String Link::removePrefix()
{
    uint i = 0;
    String prefix;

    if ( d->s[i] == '/' ) {
        i++;
        while ( i < d->s.length() && d->s[i] != '/' )
            i++;
        prefix = d->s.mid( 1, i-1 );
        d->s = d->s.mid( i );
    }

    return prefix;
}


/*! Parses a mailbox name. If there isn't any, registers an error. */

void Link::parseMailbox()
{
    Mailbox *m = 0;

    if ( d->s[0] != '/' ) {
        error( "No mailbox id present" );
        return;
    }

    uint i = 1;
    while ( d->s[i] >= '0' && d->s[i] <= '9' )
        i++;
    if ( i > 0 ) {
        bool ok = false;
        uint id = d->s.mid( 1, i-1 ).number( &ok );
        if ( ok ) {
            d->s = d->s.mid( i );
            m = Mailbox::find( id );
        }
    }

    if ( !m )
        error( "Could not find valid mailbox id: " + d->s );

    d->mailbox = m;
}



/*! Records \a msg as a parse error, assuming that no other error has
    been recorded yet. Only the first error is recorded/reported.
*/

void Link::error( const String & msg )
{
    d->type = Error;
    if ( d->error.isEmpty() )
        d->error = msg;
}


/*! Returns the error message corresponding to the first error seen
    while parsing the link, or an empty string if all is well.
*/

String Link::errorMessage() const
{
    return d->error;
}


/*! Returns a pointer to the mailbox identified by this link, or 0 if
    there is no such mailbox, or if this link does not identify a
    mailbox.
*/

Mailbox *Link::mailbox() const
{
    return d->mailbox;
}


/*! Returns the type of this Link, which may be ArchiveMailbox,
    WebmailMailbox, Webmail, ArchiveMessage, WebmailMessage, or Error.
*/

Link::Type Link::type() const
{
    return d->type;
}
