// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "link.h"

#include "list.h"
#include "mailbox.h"
#include "message.h"
#include "configuration.h"
#include "permissions.h"
#include "estringlist.h"
#include "webpage.h"
#include "http.h"
#include "utf.h"

#include "components/error301.h"
#include "components/error404.h"
#include "components/archivemailboxes.h"
#include "components/archivemailbox.h"
#include "components/archivemessage.h"
#include "components/archivesearch.h"
#include "components/archivethread.h"
#include "components/formmail.h"
#include "components/sendmail.h"
#include "components/searchbox.h"
#include "components/mailboxlist.h"
#include "components/viewlist.h"
#include "components/editview.h"
#include "components/addview.h"
#include "components/webmailindex.h"


class LinkData
    : public Garbage
{
public:
    LinkData()
        : type( Link::Error ), magic( false ), views( false ),
          mailbox( 0 ), uid( 0 ), suffix( Link::None ),
          arguments( new Dict<Link::Argument> ),
          webpage( 0 ), server( 0 ), secure( false )
    {}

    EString original;

    Link::Type type;
    bool magic;
    bool views;
    Mailbox * mailbox;
    uint uid;
    EString part;
    Link::Suffix suffix;
    Dict<Link::Argument> * arguments;

    WebPage * webpage;

    HTTP * server;
    bool secure;
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

Link::Link( const EString &s, HTTP * server )
    : d( new LinkData )
{
    d->server = server;
    if ( server->hasTls() )
        setSecure();
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


/*! Returns true if this Link is magic (i.e. belongs to the magic
    /archiveopteryx hierarchy), and false otherwise. */

bool Link::magic() const
{
    return d->magic;
}


/*! Sets this Link's magicity to \a m. */

void Link::setMagic( bool m )
{
    d->magic = m;
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

EString Link::part() const
{
    return d->part;
}


/*! Sets this Link's part number to \a part. */

void Link::setPart( const EString & part )
{
    d->part = part;
}


/*! Returns this Link's suffix, which is None by default, but may be any
    of the values in the enum Link::Suffix.
*/

Link::Suffix Link::suffix() const
{
    return d->suffix;
}


/*! Sets this Link's suffix to \a suffix. */

void Link::setSuffix( Suffix suffix )
{
    d->suffix = suffix;
}


/*! Returns a non-zero pointer to a (possibly empty) Dict that contains
    the parameters from the query component of this Link.
*/

Dict<Link::Argument> * Link::arguments() const
{
    return d->arguments;
}


/*! Returns the specified query string, if any, or an empty string. */

EString Link::query() const
{
    EString s;
    Utf8Codec c;
    Dict<Argument>::Iterator it( d->arguments );
    while ( it ) {
        s.append( it->name );
        s.append( "=" );
        EString v = c.fromUnicode( it->value );
        uint i = 0;
        while ( i < v.length() ) {
            char c = v[i];
            ++i;
            if ( c == '&' || c == '%' || c == '+' || c > 'z' ) {
                s.append( '%' );
                EString num = EString::fromNumber( c, 16 ).lower();// XXX lower?
                if ( num.length() < 2 )
                    s.append( '0' );
                s.append( num );
            }
            else if ( c == ' ' ) {
                s.append( '+' );
            }
            else {
                s.append( c );
            }
        }
        ++it;
        if ( it )
            s.append( "&" );
    }

    return s;
}


/*! Returns the URL passed to the constructor. */

EString Link::original() const
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


/*! Tells this Link that it refers to an HTTPS server. */

void Link::setSecure()
{
    d->secure = true;
}


static WebPage * errorPage( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new Error404( link ) );
    return p;
}


static WebPage * trailingSlash( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new Error301( link ) );
    return p;
}


static WebPage * secureRedirect( Link * link )
{
    WebPage * p = new WebPage( link );
    link->setSecure();
    p->addComponent( new Error301( link ) );
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
    p->addComponent( new SearchBox );
    p->addComponent( new ArchiveMailbox( link ) );
    return p;
}


static WebPage * archiveSearch( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new SearchBox );
    p->addComponent( new ArchiveSearch( link ) );
    return p;
}


static WebPage * archiveThread( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new SearchBox );
    p->addComponent( new ArchiveThread( link ) );
    return p;
}


static WebPage * archiveMessage( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new ArchiveMessage( link ) );
    return p;
}


static WebPage * webmailMailboxes( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new WebmailIndex );
    p->addComponent( new MailboxList );
    p->addComponent( new ViewList );
    p->addComponent( new EditView );
    return p;
}

static WebPage * webmailMailbox( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new ArchiveMailbox( link ) );
    return p;
}


static WebPage * webmailThread( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new ArchiveThread( link ) );
    return p;
}


static WebPage * webmailMessage( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new ArchiveMessage( link ) );
    p->addComponent( new FormMail );
    return p;
}


static WebPage * webmailListViews( Link * link )
{
    WebPage * p = new PageFragment( link );
    p->addComponent( new ViewList );
    return p;
}


static WebPage * webmailAddView( Link * link )
{
    WebPage * p = new PageFragment( link );
    p->addComponent( new AddView );
    return p;
}


static WebPage * messagePage( Link * link )
{
    return new MessagePage( link );
}


static WebPage * partPage( Link * link )
{
    return new BodypartPage( link );
}


static WebPage * sendmail( Link * link )
{
    WebPage * p = new WebPage( link );
    p->addComponent( new Sendmail );
    return p;
}


enum Component {
    ArchivePrefix, WebmailPrefix,
    Magic, MailboxName, Uid, Part, Suffix, Arguments,
    Void,
    NumComponents
};


static const struct Handler {
    Component components[5];
    WebPage *(*handler)( Link * );
} handlers[] = {
    { { ArchivePrefix, Void,        Void, Void,     Void }, &archiveMailboxes },
    { { ArchivePrefix, MailboxName, Void, Void,     Void }, &archiveMailbox },
    { { ArchivePrefix, MailboxName, Arguments, Void,Void }, &archiveSearch },
    { { ArchivePrefix, MailboxName, Uid,  Suffix,   Void }, &archiveMessage },
    { { ArchivePrefix, MailboxName, Uid,  Part,     Void }, &partPage },
    { { WebmailPrefix, Void,        Void, Void,     Void }, &webmailMailboxes },
    { { WebmailPrefix, MailboxName, Void, Void,     Void }, &webmailMailbox },
    { { WebmailPrefix, MailboxName, Uid,  Suffix,   Void }, &webmailMessage },
    { { WebmailPrefix, MailboxName, Uid,  Part,     Void }, &partPage },
    { { WebmailPrefix, Magic,       Suffix, Void,   Void }, &errorPage }
};
static uint numHandlers = sizeof( handlers ) / sizeof( handlers[0] );


static const struct {
    const char * name;
    Link::Suffix suffix;
    WebPage *(*handler)( Link * );
    WebPage *(*suffixHandler)( Link * );
} suffixes[] = {
    { "thread", Link::Thread, &archiveMessage, &archiveThread },
    { "rfc822", Link::Rfc822, &archiveMessage, &messagePage },
    { "thread", Link::Thread, &webmailMessage, &webmailThread },
    { "rfc822", Link::Rfc822, &webmailMessage, &messagePage },
    { "send",   Link::Send,   &errorPage,      &sendmail },
    { "views/list", Link::ListViews, &errorPage, &webmailListViews },
    { "views/add", Link::AddView, &errorPage, &webmailAddView }
};
static uint numSuffixes = sizeof( suffixes ) / sizeof( suffixes[0] );


static bool checkPrefix( LinkParser * p, const EString & s, bool legal )
{
    if ( !legal )
        return false;

    p->mark();

    EStringList * want = EStringList::split( '/', s );
    EStringList::Iterator it( want );
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


static Component checkPrefixes( LinkParser * p,
                                bool legalComponents[NumComponents] )
{
    Component e = Void;
    Component c = ArchivePrefix;
    while ( c <= WebmailPrefix ) {
        EString s;
        Configuration::Text var;
        Configuration::Toggle use;
        switch ( c ) {
        case ArchivePrefix:
            var = Configuration::ArchivePrefix;
            use = Configuration::UseWebArchive;
            break;
        case WebmailPrefix:
            var = Configuration::WebmailPrefix;
            use = Configuration::UseWebmail;
            break;
        default:
            return Void;
            break;
        }
        s = Configuration::text( var );
        if ( !Configuration::toggle( use ) )
            ;
        else if ( s.isEmpty() && legalComponents[c] )
            e = c;
        else if ( checkPrefix( p, s, legalComponents[c] ) )
            return c;
        c = (Component)(c + 1);
    }

    return e;
}


/*! Parses \a s as a http path. \a s must begin with a slash and
    cannot contain any escape sequences.
*/

void Link::parse( const EString & s )
{
    List< const Handler > h;

    d->original = s;

    uint i = 0;
    while ( i < numHandlers ) {
        h.append( &handlers[i] );
        i++;
    }

    LinkParser * p = new LinkParser( s );

    i = 0;
    while ( i < 5 ) {
        bool legalComponents[NumComponents];
        uint n = 0;
        while ( n < NumComponents )
            legalComponents[n++] = false;

        List<const Handler>::Iterator it( h );
        while ( it ) {
            legalComponents[it->components[i]] = true;
            ++it;
        }

        Component chosen = Void;

        chosen = checkPrefixes( p, legalComponents );
        if ( chosen == ArchivePrefix )
            setType( Archive );
        else if ( chosen == WebmailPrefix )
            setType( Webmail );

        if ( chosen == Void && legalComponents[Magic] ) {
            p->mark();
            p->require( "/archiveopteryx" );
            if ( p->ok() ) {
                chosen = Magic;
                setMagic( true );
            }
            else {
                p->restore();
            }
        }

        if ( chosen == Void && legalComponents[MailboxName] ) {
            Mailbox * m = Mailbox::root();

            p->mark();
            EString seen;
            while ( p->present( "/" ) ) {
                EString have( p->pathComponent().lower() );
                List<Mailbox>::Iterator it( m->children() );
                while ( it ) {
                    EString name( seen + "/" + have );
                    if ( name == it->name().utf8().lower() ) {
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

        if ( chosen == Void && legalComponents[Uid] ) {
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

        if ( chosen == Void && legalComponents[Part] ) {
            p->mark();
            p->require( "/" );
            EString part( p->digits( 1, 10 ) );
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

        if ( chosen == Void && legalComponents[::Suffix] ) {
            p->mark();
            if ( p->present( "/" ) ) {
                List<const Handler>::Iterator it( h );
                while ( chosen == Void && it ) {
                    if ( it->components[i] == ::Suffix ) {
                        uint j = 0;
                        while ( chosen == Void && j < numSuffixes ) {
                            if ( suffixes[j].handler == it->handler &&
                                 p->present( suffixes[j].name ) )
                            {
                                chosen = ::Suffix;
                                setSuffix( suffixes[j].suffix );
                            }
                            j++;
                        }
                    }
                    ++it;
                }
                if ( chosen == Void )
                    p->restore();
            }
            else {
                chosen = ::Suffix;
                p->restore();
            }
        }

        if ( chosen == Void && legalComponents[::Arguments] ) {
            Dict<EString> args;
            p->mark();
            p->require( "?" );
            while ( !p->atEnd() ) {
                EString n, v;
                while ( p->nextChar() != '=' &&
                        p->nextChar() != '&' &&
                        !p->atEnd() )
                    n.append( p->character() );
                n = n.deURI();
                if ( p->present( "=" ) ) {
                    while ( p->nextChar() != '&' && !p->atEnd() )
                        v.append( p->character() );
                }
                UString u = decoded( v );
                if ( n.boring() && !u.isEmpty() )
                    addArgument( n, u );
                if ( p->nextChar() == '&' )
                    p->step();
            }
            if ( p->ok() ) {
                chosen = ::Arguments;
            } else {
                d->arguments = new Dict<Argument>;
                p->restore();
            }
        }

        if ( chosen == Void && legalComponents[Void] ) {
            if ( p->atEnd() ) {
                // ok - we've reached the end and reaching the end is
                // legal
            }
            else if ( p->pos() == 0 && p->input() == "/" ) {
                // ok - it's "/" and we normally take slashes along
                // with the component following them.
                p->step();
            }
            else {
                // we couldn't use the rest of the string.
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
        if ( i < 5 && chosen == Void && h.count() <= 1 )
            i = 5;
    }

    if ( p->input().mid( p->pos() ) == "/" ) {
        // it's a valid URL with a trailing slash. we redirect.
        d->webpage = trailingSlash( this );
    }
    else if ( h.count() == 1 && p->atEnd() &&
              ( i >= 5 || h.first()->components[i] == Void ) )
    {
        WebPage *(*handler)( Link * ) = h.first()->handler;
        if ( d->suffix != None ) {
            uint j = 0;
            while ( j < numSuffixes ) {
                if ( suffixes[j].handler == handler &&
                     suffixes[j].suffix == d->suffix )
                {
                    handler = suffixes[j].suffixHandler;
                    break;
                }
                j++;
            }
        }
        if ( d->server->accessPermitted() )
            d->webpage = handler( this );
        else
            d->webpage = secureRedirect( this );
    }
    else {
        d->webpage = errorPage( this );
    }

    if ( webPage() && mailbox() )
        webPage()->requireRight( mailbox(), Permissions::Read );
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

EString Link::canonical() const
{
    Component prefix = ArchivePrefix; // set it just to silence gcc -O3
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

        if ( good && handlers[i].components[0] != prefix )
            good = false;

        good = good &&
               checkForComponent( i, Magic, d->magic ) &&
               checkForComponent( i, MailboxName, d->mailbox ) &&
               checkForComponent( i, Uid, d->uid != 0 ) &&
               checkForComponent( i, Part, !d->part.isEmpty() ) &&
               checkForComponent( i, Arguments, !d->arguments->isEmpty() );

        uint c = 0;
        while ( good && c < 5 && handlers[i].components[c] != Void )
            c++;

        if ( good && c < shortest ) {
            shortest = c;
            chosen = i;
        }

        i++;
    }

    EString r;

    uint c = 0;
    while ( c < 5 ) {
        switch ( handlers[chosen].components[c] ) {
        case ArchivePrefix:
            r.append( Configuration::text( Configuration::ArchivePrefix ) );
            break;
        case WebmailPrefix:
            r.append( Configuration::text( Configuration::WebmailPrefix ) );
            break;
        case Magic:
            r.append( "/archiveopteryx" );
            break;
        case MailboxName:
            r.append( d->mailbox->name().utf8().eURI() );
            break;
        case Uid:
            r.append( "/" );
            r.appendNumber( d->uid );
            break;
        case Part:
            r.append( "/" );
            r.append( d->part );
            break;
        case ::Suffix:
            if ( d->suffix != None ) {
                uint j = 0;
                while ( j < numSuffixes &&
                        suffixes[j].suffix != d->suffix )
                    j++;
                r.append( "/" );
                r.append( suffixes[j].name );
            }
            break;
        case ::Arguments:
            r.append( "?" );
            r.append( query() );
            break;
        case Void:
        case NumComponents:
            break;
        }
        c++;
    }

    if ( r.isEmpty() )
        r = "/";

    return r;
}


/*! Returns an absolute version of this Link, including scheme and
    hostname and stuff.

    This is used to redirect to the HTTPS version of a URL when
    allow-plaintext-access requires it.
*/

EString Link::absolute() const
{
    EString s;

    if ( d->secure )
        s.append( "https" );
    else
        s.append( "http" );
    s.append( "://" );
    EString hn;
    if ( Configuration::toggle( Configuration::AcceptAnyHttpHost ) )
        hn = d->server->hostHeader();
    else
        hn = Configuration::hostname();
    if ( hn.isEmpty() )
        hn = d->server->self().address();
    s.append( hn );

    uint port = Configuration::scalar( Configuration::HttpPort );
    if ( d->secure )
        port = Configuration::scalar( Configuration::HttpsPort );
    if ( ( d->secure && port != 443 ) || ( !d->secure && port != 80 ) ) {
        s.append( ":" );
        s.appendNumber( port );
    }

    s.append( canonical() );
    return s;
}



/*! \class LinkParser link.h
    Returns components from a URL.

    This class accepts a request URL and returns bits and pieces of it.
*/

/*! Creates a new LinkParser to parse \a s. */

LinkParser::LinkParser( const EString & s )
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
        EString a;
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

EString LinkParser::pathComponent()
{
    EString r;

    while ( nextChar() != '/' && nextChar() != '&' &&
            nextChar() != '?' && !atEnd() )
        r.append( character() );

    return r;
}


/*! Adds another query argument to this Link, \a name = \a value. \a
    name must always be a nonempty boring ascii string (by design
    fiat), \a value can contain any unicode.
*/

void Link::addArgument( const EString & name, const UString & value )
{
    if ( !name.boring() )
        return;
    d->arguments->insert( name, new Argument( name, value ) );
}


/*! Returns a decoded version of \a s, or an empty string if \a s is
    somehow bad.
*/

UString Link::decoded( const EString & s )
{
    UString r;
    Utf8Codec c;
    EString v8;
    uint i = 0;
    while ( i < s.length() ) {
        char c = s[i];
        i++;
        if ( c == '+' ) {
            v8.append( ' ' );
        }
        else if ( c == '%' ) {
            bool ok = true;
            uint n = s.mid( i, 2 ).number( &ok, 16 );
            if ( ok ) {
                i += 2;
                v8.append( (char)n );
            }
            else {
                return r;
            }
        }
        else {
            v8.append( c );
        }
    }
    r = c.toUnicode( v8 );
    if ( !c.valid() )
        r.truncate();
    return r;
}


/*! Returns the value of argument \a s, if \a s is present. Returns
    an empty string if \a s is not present or had any kind of syntax
    error.
*/

UString Link::argument( const EString & s ) const
{
    Argument * u = d->arguments->find( s );
    UString r;
    if ( u )
        r = u->value;
    return r;
}
