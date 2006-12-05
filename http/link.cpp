// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "link.h"

#include "mailbox.h"
#include "message.h"
#include "configuration.h"
#include "stringlist.h"
#include "webpage.h"

#include "components/error404.h"
#include "components/archivemailboxes.h"
#include "components/archivemailbox.h"
#include "components/archivemessage.h"


class LinkData
    : public Garbage
{
public:
    LinkData()
        : type( Link::Error ), mailbox( 0 ), uid( 0 ), webpage( 0 ),
          server( 0 )
    {}

    String original;

    Link::Type type;
    Mailbox * mailbox;
    uint uid;
    String part;

    WebPage * webpage;

    HTTP * server;
};


/*! \class Link link.h
    Creates a WebPage based on a request URL.

    The Link class parses a URL and creates a WebPage object with the
    appropriate components to serve the request.
*/


/*! Constructs an empty Link. */

Link::Link()
    : d( new LinkData )
{
}


/*! Constructs and parses a link with path \a s for the HTTP server
    \a server.
*/

Link::Link( const String &s, HTTP * server )
    : d( new LinkData )
{
    d->server = server;
    parse( s );
}


/*! Returns the type of this Link, which may be any one of the values
    of the Link::Type enum (e.g. Archive, Webmail, Error).
*/

Link::Type Link::type() const
{
    return d->type;
}


/*! Sets the type of this link to \a p. The initial value is Error.
*/

void Link::setType( Type p )
{
    d->type = p;
}


/*! Returns a pointer to the mailbox identified by this link, and 0 if
    this Link does not identify a mailbox, or if the specified mailbox
    does not exist.
*/

Mailbox * Link::mailbox() const
{
    return d->mailbox;
}


/*! Sets this Link's Mailbox to \a m. */

void Link::setMailbox( Mailbox * m )
{
    d->mailbox = m;
}


/*! Returns this Link's UID, if there is one, and 0 otherwise. */

uint Link::uid() const
{
    return d->uid;
}


/*! Sets this Link's UID to \a uid. */

void Link::setUid( uint uid )
{
    d->uid = uid;
}


/*! Returns the part number of the message identified by this Link, if
    there is one; or an empty string otherwise. The part number is a
    valid IMAP part number, but may not be valid for the message in
    question.
*/

String Link::part() const
{
    return d->part;
}


/*! Sets this Link's part number to \a part. */

void Link::setPart( const String & part )
{
    d->part = part;
}


/*! Returns the URL passed to the constructor. */

String Link::original() const
{
    return d->original;
}


/*! Returns a pointer to the WebPage object that this Link represents,
    or 0 if this Link was not constructed from a request URL.
*/

WebPage * Link::webPage() const
{
    return d->webpage;
}


/*! Returns a pointer to this Link's server, if one was specified during
    construction, and 0 otherwise.
*/

HTTP * Link::server() const
{
    return d->server;
}


static WebPage * errorPage( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new Error404( link ) );
    return p;
}


static WebPage * archiveMailboxes( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new ArchiveMailboxes );
    return p;
}


static WebPage * archiveMailbox( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new ArchiveMailbox( link ) );
    return p;
}


static WebPage * archiveMessage( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new ArchiveMessage( link ) );
    return p;
}


static WebPage * archivePart( Link * link )
{
    return new BodypartPage( link );
}


enum Component {
    ArchivePrefix, WebmailPrefix,
    MailboxName, Uid, Part, None,
    NumComponents
};


static const struct Handler {
    Component components[5];
    WebPage *(*handler)( Link * );
} handlers[] = {
    { { ArchivePrefix, None,        None, None, None }, &archiveMailboxes },
    { { ArchivePrefix, MailboxName, None, None, None }, &archiveMailbox },
    { { ArchivePrefix, MailboxName, Uid,  None, None }, &archiveMessage },
    { { ArchivePrefix, MailboxName, Uid,  Part, None }, &archivePart }
};
static uint numHandlers = sizeof( handlers ) / sizeof( handlers[0] );


static bool checkPrefix( LinkParser * p, Component c, bool legal )
{
    if ( !legal )
        return false;

    p->mark();

    Configuration::Text var;
    switch ( c ) {
    case ArchivePrefix:
        var = Configuration::ArchivePrefix;
        break;
    case WebmailPrefix:
        var = Configuration::WebmailPrefix;
        break;
    default:
        return false;
        break;
    }

    StringList * want = StringList::split( '/', Configuration::text( var ) );
    StringList::Iterator it( want );
    if ( it && it->isEmpty() )
        ++it;
    while ( it ) {
        p->require( "/" );
        if ( p->pathComponent() != *it ) {
            p->restore();
            return false;
        }
        ++it;
    }

    return true;
}


/*! Parses \a s as a http path. \a s must begin with a slash and
    cannot contain any escape sequences.
*/

void Link::parse( const String & s )
{
    List< const Handler > h;

    d->original = s;

    uint i = 0;
    while ( i < numHandlers ) {
        h.append( &handlers[i] );
        i++;
    }

    LinkParser * p = new LinkParser( s );

    // All URLs are irretrievably hideous.

    i = 0;
    while ( !p->atEnd() && i < 5 ) {
        bool legalComponents[NumComponents];
        uint n = 0;
        while ( n < NumComponents )
            legalComponents[n++] = false;

        List<const Handler>::Iterator it( h );
        while ( it ) {
            legalComponents[it->components[i]] = true;
            ++it;
        }

        Component chosen = None;

        if ( checkPrefix( p, ArchivePrefix, legalComponents[ArchivePrefix] ) ) {
            chosen = ArchivePrefix;
            setType( Archive );
        }

        if ( chosen == None &&
             checkPrefix( p, WebmailPrefix, legalComponents[WebmailPrefix] ) )
        {
            chosen = WebmailPrefix;
            setType( Webmail );
        }

        if ( chosen == None && legalComponents[MailboxName] ) {
            Mailbox * m = Mailbox::root();

            p->mark();
            String seen;
            while ( p->present( "/" ) ) {
                String have( p->pathComponent().lower() );
                List<Mailbox>::Iterator it( m->children() );
                while ( it ) {
                    String name( seen + "/" + have );
                    if ( name == it->name().lower() ) {
                        m = it;
                        seen = name;
                        p->mark();
                        break;
                    }
                    ++it;
                }

                if ( !it ) {
                    p->restore();
                    break;
                }
            }

            if ( m->ordinary() || m->view() ) {
                setMailbox( m );
                chosen = MailboxName;
            }
            else {
                p->restore();
            }
        }

        if ( chosen == None && legalComponents[Uid] ) {
            p->mark();
            p->require( "/" );
            uint uid = p->number();
            if ( uid != 0 && p->ok() ) {
                chosen = Uid;
                setUid( uid );
            }
            else {
                p->restore();
            }
        }

        if ( chosen == None && legalComponents[Part] ) {
            p->mark();
            p->require( "/" );
            String part( p->digits( 1, 10 ) );
            while ( p->ok() && p->present( "." ) ) {
                part.append( "." );
                part.append( p->digits( 1, 10 ) );
            }
            if ( p->ok() ) {
                chosen = Part;
                setPart( part );
            }
            else {
                p->restore();
            }
        }

        if ( chosen == None && legalComponents[None] ) {
            if ( p->atEnd() ) {
                chosen = None;
            }
            else {
                chosen = None;
            }
        }

        it = h;
        while ( it ) {
            if ( legalComponents[it->components[i]] &&
                 it->components[i] != chosen )
                h.take( it );
            else
                ++it;
        }
        i++;
    }

    if ( p->atEnd() && i < 5 ) {
        List<const Handler>::Iterator it( h );
        while ( it ) {
            if ( it->components[i] != None )
                h.take( it );
            else
                ++it;
        }
    }

    if ( h.count() == 1 &&
         ( i == 5 || h.first()->components[i] == None ) )
    {
        d->webpage = h.first()->handler( this );
    }
    else {
        d->webpage = errorPage( this );
    }
}


static bool checkForComponent( uint i, Component c, bool wanted )
{
    uint j = 0;
    while ( j < 5 ) {
        if ( handlers[i].components[j] == c ) {
            if ( wanted )
                return true;
            else
                return false;
        }
        j++;
    }

    if ( wanted )
        return false;
    else
        return true;
}


/*! Generates a path that represents this Link object. */

String Link::canonical() const
{
    Component prefix;
    switch ( d->type ) {
    case Archive:
        prefix = ArchivePrefix;
        break;
    case Webmail:
        prefix = WebmailPrefix;
        break;
    case Favicon:
        return "/favicon.ico";
        break;
    case Error:
        return "";
        break;
    }

    uint i = 0;
    uint shortest = 6;
    uint chosen = UINT_MAX;

    while ( i < numHandlers ) {
        bool good = true;

        good = checkForComponent( i, MailboxName, d->mailbox ) &&
               checkForComponent( i, Uid, d->uid != 0 ) &&
               checkForComponent( i, Part, !d->part.isEmpty() );

        if ( good && handlers[i].components[0] != prefix )
            good = false;

        uint c = 0;
        while ( good && c < 5 && handlers[i].components[c] != None )
            c++;

        if ( good && c < shortest ) {
            shortest = c;
            chosen = i;
        }

        i++;
    }

    String r;

    uint c = 0;
    while ( c < 5 ) {
        switch ( handlers[chosen].components[c] ) {
        case ArchivePrefix:
            r.append( Configuration::text( Configuration::ArchivePrefix ) );
            break;
        case WebmailPrefix:
            r.append( Configuration::text( Configuration::WebmailPrefix ) );
            break;
        case MailboxName:
            // XXX: We need to %-escape the mailbox name.
            r.append( d->mailbox->name() );
            break;
        case Uid:
            r.append( "/" );
            r.append( fn( d->uid ) );
            break;
        case Part:
            r.append( "/" );
            r.append( d->part );
            break;
        case None:
        case NumComponents:
            break;
        }
        c++;
    }

    return r;
}


/*! \class LinkParser link.h
    Returns components from a URL.

    This class accepts a request URL and returns bits and pieces of it.
*/

/*! Creates a new LinkParser to parse \a s. */

LinkParser::LinkParser( const String & s )
    : AbnfParser( s )
{
}


/*! Returns the next character from the input after stepping past it,
    unescaping %-encoded characters if necessary.
*/

char LinkParser::character()
{
    char c = nextChar();
    step();

    if ( c == '%' ) {
        bool ok;
        String a;
        a.append( nextChar() );
        step();
        a.append( nextChar() );
        step();

        c = a.number( &ok, 16 );
        if ( !ok )
            setError( "Invalid percent escape: %" + a );
    }

    return c;
}


/*! Returns the next path component from the input after stepping past
    it. A path component is something that does not contain "/", "&",
    "?".
*/

String LinkParser::pathComponent()
{
    String r;

    while ( nextChar() != '/' && nextChar() != '&' &&
            nextChar() != '?' && !atEnd() )
        r.append( character() );

    return r;
}
