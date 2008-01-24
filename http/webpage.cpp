// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "webpage.h"

#include "map.h"
#include "link.h"
#include "http.h"
#include "query.h"
#include "field.h"
#include "message.h"
#include "mailbox.h"
#include "fetcher.h"
#include "pagecomponent.h"
#include "httpsession.h"
#include "frontmatter.h"
#include "mimefields.h"
#include "ustring.h"
#include "codec.h"
#include "user.h"
#include "utf.h"

#include "components/loginform.h"


static User * archiveUser;
static Map<Permissions> * archiveMailboxPermissions;


class WebPageData
    : public Garbage
{
public:
    WebPageData()
        : link( 0 ), checker( 0 ), responded( false ),
          user( 0 ), uniq( 0 )
    {}

    struct PermissionRequired
        : public Garbage
    {
        PermissionRequired(): m( 0 ), r( Permissions::Read ) {}
        Mailbox * m;
        Permissions::Right r;
    };

    Link * link;
    List<PageComponent> components;
    List<PermissionRequired> needed;
    PermissionsChecker * checker;
    bool responded;
    User * user;
    uint uniq;
};


/*! \class WebPage webpage.h

    A WebPage is a collection of PageComponents, each with some relevant
    FrontMatter objects. It waits for all its components to assemble
    their contents, and then composes the response.
*/

/*! Creates a new WebPage to serve \a link. */

WebPage::WebPage( Link * link )
    : d( new WebPageData )
{
    d->link = link;
}


/*! Adds the PageComponent \a pc to this WebPage. If \a after is
    present and non-null, \a pc is added immediately after \a
    after. If \a after is null (this is the default), \a pc is added
    at the end. */

void WebPage::addComponent( PageComponent * pc, const PageComponent * after )
{
    List<PageComponent>::Iterator i;
    if ( after ) {
        i = d->components.find( after );
        if ( i )
            ++i;
    }
    if ( i )
        d->components.insert( i, pc );
    else
        d->components.append( pc );

    pc->setPage( this );
}


/*! Returns a non-zero pointer to this WebPage's Link object. */

Link * WebPage::link() const
{
    return d->link;
}


void WebPage::execute()
{
    if ( d->responded )
        return;

    if ( !permitted() )
        return;

    bool done = true;
    uint status = 200;
    uint c = 0;
    while ( c != d->components.count() ) {
        c = d->components.count();
        List<PageComponent>::Iterator it( d->components );
        while ( it ) {
            PageComponent * p = it;
            ++it;
            if ( !p->done() ) {
                p->execute();
                done = false;
            }
            if ( p->status() > status )
                status = p->status();
        }
    }

    if ( !done )
        return;

    d->link->server()->setStatus( status, "OK" );
    d->link->server()->respond( "text/html; charset=utf-8", html() );
    d->responded = true;
}


/*! Returns the HTML output of this page, as it currently looks. The
    return value isn't sensible until all pages are ready, as
    execute() checks.
*/

String WebPage::html() const
{
    List<FrontMatter> frontMatter;

    frontMatter.append( FrontMatter::styleSheet() );

    List<PageComponent>::Iterator it( d->components );
    while ( it ) {
        List<FrontMatter>::Iterator f( it->frontMatter() );
        while ( f ) {
            frontMatter.append( f );
            ++f;
        }
        ++it;
    }

    String html(
        "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n"
        "<html><head>\n"
    );

    List<FrontMatter>::Iterator f( frontMatter );
    while ( f ) {
        html.append( *f );
        html.append( "\n" );
        ++f;
    }

    html.append( "</head><body>\n" );

    it = d->components;
    while ( it ) {
        html.append( it->contents() );
        ++it;
    }

    html.append( "</body>\n" );
    return html;
}



/*! Notes that this WebPage requires \a r on \a m. execute() should
    proceed only if and when permitted() is true.
*/

void WebPage::requireRight( Mailbox * m, Permissions::Right r )
{
    WebPageData::PermissionRequired * pr = new WebPageData::PermissionRequired;
    pr->m = m;
    pr->r = r;
    d->needed.append( pr );
}


/*! Returns true if this WebPage has the rights demanded by
    requireRight(), and is permitted to proceed, and false if
    it either must abort due to lack of rights or wait until
    Permissions has fetched more information.

    If permitted() denies permission, it also sets a suitable error
    message.
*/

bool WebPage::permitted()
{
    if ( d->responded )
        return false;

    if ( d->needed.isEmpty() )
        return true;

    HTTP * server = d->link->server();
    UString login( server->parameter( "login" ) );

    if ( d->user ) {
        // leave it
    }
    else if ( d->link->type() == Link::Archive ) {
        if ( !::archiveUser ) {
            ::archiveUser = new User;
            UString u;
            u.append( "anonymous" );
            ::archiveUser->setLogin( u );
            ::archiveUser->refresh( this );
            Allocator::addEternal( ::archiveUser, "anonymous archive user" );
        }
        d->user = ::archiveUser;
    }
    else if ( !login.isEmpty() ) {
        d->user = new User;
        d->user->setLogin( login );
        d->user->refresh( this );
    }
    else if ( server->session() ) {
        d->user = server->session()->user();
    }

    if ( !d->user ) {
        sendLoginForm();
        return false;
    }

    if ( d->user->state() == User::Unverified ) {
        d->user->refresh( this );
        return false;
    }

    if ( !d->checker ) {
        bool anon = false;
        if ( d->user && d->user->login() == "anonymous" )
            anon = true;
        d->checker = new PermissionsChecker;
        List<WebPageData::PermissionRequired>::Iterator i( d->needed );
        while ( i ) {
            Permissions * p = d->checker->permissions( i->m, d->user );
            if ( p ) {
                // just use that
            }
            else if ( d->user->state() != User::Refreshed ) {
                // don't add anything
            }
            else if ( !anon ) {
                p = new Permissions( i->m, d->user, this );
            }
            else {
                if ( !::archiveMailboxPermissions ) {
                    ::archiveMailboxPermissions = new Map<Permissions>;
                    Allocator::addEternal( ::archiveMailboxPermissions,
                                           "archives permissions checkers" );
                }
                p = ::archiveMailboxPermissions->find( i->m->id() );
                if ( !p ) {
                    p = new Permissions( i->m, d->user, this );
                    ::archiveMailboxPermissions->insert( i->m->id(), p );
                }
            }
            if ( p )
                d->checker->require( p, i->r );
            ++i;
        }
    }
    
    // If we don't have a checker, we permit the request. Link calls
    // requireRight as soon as it sees a mailbox name in the URL, so
    // this should be true only for a few globally accessibly pages.
    if ( !d->checker )
        return true;

    if ( d->checker && !d->checker->ready() )
        return false;

    if ( d->link->type() == Link::Archive ) {
        if ( d->user->state() == User::Refreshed &&
             d->checker && d->checker->allowed() )
            return true;
        d->responded = true;
        server->setStatus( 403, "Forbidden" );
        server->respond( "text/plain",
                         d->checker->error().simplified() + "\n" );
        return false;
    }
    else {
        UString passwd( server->parameter( "passwd" ) );
        if ( d->user->state() != User::Refreshed ||
             d->user->secret() != passwd ||
             !d->checker ||
             !d->checker->allowed() )
        {
            sendLoginForm();
            return false;
        }
        else {
            HttpSession * s = server->session();
            if ( !s || s->user()->login() != d->user->login() ) {
                s = new HttpSession;
                server->setSession( s );
            }
            s->setUser( d->user );
            s->refresh();
            return true;
        }
    }

    return false;
}


/*! Rewrites this page to be a plain login form which will reload the
    same page when the correct password is entered.
*/

void WebPage::sendLoginForm()
{
    d->responded = true;
    d->needed.clear();
    d->checker = 0;
    d->components.clear();
    PageComponent * lf = new LoginForm;
    addComponent( lf );
    lf->execute();
    d->link->server()->setStatus( 200, "OK" );
    d->link->server()->respond( "text/html; charset=utf-8", html() );
}


class BodypartPageData
    : public Garbage
{
public:
    BodypartPageData()
        : b( 0 ), c( 0 )
    {}

    Query * b;
    Query * c;
};


/*! \class BodypartPage webpage.h
    A subclass of WebPage, meant to serve message unadorned bodyparts.
*/

/*! Creates a BodypartPage object to serve \a link, which must refer to
    a message, uid, and part number (which may or may not be valid).
*/

BodypartPage::BodypartPage( Link * link )
    : WebPage( link ),
      d( new BodypartPageData )
{
}


void BodypartPage::execute()
{
    if ( !d->b ) {
        requireRight( link()->mailbox(), Permissions::Read );

        d->b = new Query(
            "select text, data from bodyparts b join "
            "part_numbers p on (p.bodypart=b.id) join "
            "mailbox_messages mm on (mm.message=p.message) "
            "where mm.mailbox=$1 and mm.uid=$2 and p.part=$3",
            this
        );
        d->b->bind( 1, link()->mailbox()->id() );
        d->b->bind( 2, link()->uid() );
        d->b->bind( 3, link()->part() );
        d->b->execute();

        d->c = new Query(
            "select value from header_fields hf join mailbox_messages mm "
            "on (mm.message=hf.message) where mm.mailbox=$1 and mm.uid=$2 "
            "and (hf.part=$3 or hf.part=$4) and hf.field=$5 "
            "order by part<>$3",
            this
        );
        d->c->bind( 1, link()->mailbox()->id() );
        d->c->bind( 2, link()->uid() );

        String part( link()->part() );
        d->c->bind( 3, part );
        if ( part == "1" )
            d->c->bind( 4, "" );
        else if ( part.endsWith( ".1" ) )
            d->c->bind( 4, part.mid( 0, part.length()-1 ) + "rfc822" );
        else
            d->c->bind( 4, part );

        d->c->bind( 5, HeaderField::ContentType );
        d->c->execute();
    }

    if ( !permitted() )
        return;

    if ( !d->b->done() || !d->c->done() )
        return;

    Row * r;

    String t( "text/plain" );
    r = d->c->nextRow();
    if ( r )
        t = r->getString( "value" );

    String b;
    r = d->b->nextRow();

    if ( !r ) {
        // XXX: Invalid part
    }
    else if ( r->isNull( "data" ) ) {
        b = r->getString( "text" );

        ContentType * ct = new ContentType;
        ct->parse( t );

        if ( !ct->parameter( "charset" ).isEmpty() ) {
            Utf8Codec u;
            Codec * c = Codec::byName( ct->parameter( "charset" ) );
            if ( c )
                b = c->fromUnicode( u.toUnicode( b ) );
            else
                ct->addParameter( "charset", "utf-8" );
        }
    }
    else {
        b = r->getString( "data" );
    }

    link()->server()->respond( t, b );
}


class Rfc822PageData
    : public Garbage
{
public:
    Rfc822PageData()
        : message( 0 )
    {}

    Message * message;
};


/*! \class Rfc822Page webpage.h
    Renders a single RFC822 message.
*/


Rfc822Page::Rfc822Page( Link * link )
    : WebPage( link ),
      d( new Rfc822PageData )
{
}


void Rfc822Page::execute()
{
    if ( !d->message ) {
        Mailbox * m = link()->mailbox();

        requireRight( m, Permissions::Read );

        d->message = new Message;
        d->message->setUid( link()->uid() );
        List<Message> messages;
        messages.append( d->message );

        Fetcher * f;

        f = new MessageHeaderFetcher( m, &messages, this );
        f->execute();

        f = new MessageBodyFetcher( m, &messages, this );
        f->execute();

        f = new MessageAddressFetcher( m, &messages, this );
        f->execute();
    }

    if ( !permitted() )
        return;

    if ( !( d->message->hasHeaders() &&
            d->message->hasAddresses() &&
            d->message->hasBodies() ) )
        return;

    link()->server()->respond( "message/rfc822", d->message->rfc822() );
}


/*! Returns a different nonzero number each time called. For use by
    components who need to make unique identifiers of some kind.
*/

uint WebPage::uniqueNumber()
{
    return ++d->uniq;
}
