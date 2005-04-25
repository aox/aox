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
        : type( Link::Unknown ), mailbox( 0 ), uid( 0 )
    {}

    String path;

    Link::Type type;
    Mailbox * mailbox;
    uint uid;
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


/*! Returns the type of this Link, which may be ArchiveMailbox,
    WebmailMailbox, Webmail, ArchiveMessage, WebmailMessage, or Unknown.
*/

Link::Type Link::type() const
{
    return d->type;
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


/*! Parses \a s as a http path. \a s must begin with a slash and
    cannot contain any escape sequences.
*/

void Link::parse( const String & s )
{
    StringList *l = StringList::split( '/', s );
    StringList::Iterator it( l->first() );

    d->path = s;

    // We must assume that the path starts with a /.
    if ( !it || !it->isEmpty() || !++it )
        return;

    if ( it->isEmpty() ) {
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
    case Unknown:
        s = d->path;
        break;
    }
    return s;
}


/*! Tries to parse \a s as a message uid. */

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


/*! Tries to parse \a s as a mailbox id. */

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
        d->type = Unknown;
    d->mailbox = m;
}
