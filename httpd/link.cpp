// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "link.h"

#include "http.h"
#include "user.h"
#include "page.h"
#include "mailbox.h"
#include "message.h"
#include "stringlist.h"


class LinkData {
public:
    LinkData()
        : type( Link::Error ), mailbox( 0 ), uid( 0 )
    {}

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
    StringList l;

    uint n = 0;
    uint last = 0;
    do {
        String w;
        n = s.find( ' ', last );
        if ( n > 0 ) {
            w = s.mid( last+1, n-last-1 );
            n++;
        }
        else {
            w = s.mid( last+1 );
        }
        last = n;

        if ( !w.isEmpty() )
            l.append( w );
    }
    while ( last > 0 );

    StringList::Iterator it( l.first() );
    if ( !it ) {
        d->type = Webmail;
    }
    else if ( *it == "archive" ) {
        d->type = ArchiveMailbox;
        parseMailbox( ++it );
        parseUid( ++it );
    }
    else {
        d->type = WebmailMailbox;
        parseMailbox( it );
        parseUid( ++it );
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
        s = "/" + fn( d->mailbox->id() );
        break;
    case Webmail:
        s = "/";
        break;
    case ArchiveMessage:
        s = "/archive/" + fn( d->mailbox->id() ) + "/" + fn( d->uid );
        break;
    case WebmailMessage:
        s = "/" + fn( d->mailbox->id() ) + "/" + fn( d->uid );
        break;
    case Error:
        break;
    }
    return s;
}


/*! Parses a UID in \a s. */

void Link::parseUid( const String *s )
{
    if ( !s )
        return;

    bool ok = false;
    d->uid = s->number( &ok );
    if ( ok ) {
        if ( d->type == ArchiveMailbox )
            d->type = ArchiveMessage;
        else if ( d->type == WebmailMailbox )
            d->type = WebmailMessage;
    }
}


/*! Parses a mailbox id in \a s. If there isn't any, registers an error. */

void Link::parseMailbox( const String *s )
{
    Mailbox *m = 0;

    if ( !s )
        return;

    bool ok = false;
    uint id = s->number( &ok );
    if ( ok )
        m = Mailbox::find( id );
    if ( !m )
        error( "Could not find valid mailbox id" );
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


/*! Returns the UID, if this Link contains a UID, or 0 if not.
*/

uint Link::uid() const
{
    return d->uid;
}


/*! Returns the type of this Link, which may be ArchiveMailbox,
    WebmailMailbox, Webmail, ArchiveMessage, WebmailMessage, or Error.
*/

Link::Type Link::type() const
{
    return d->type;
}
