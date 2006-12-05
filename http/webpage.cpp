// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "webpage.h"

#include "link.h"
#include "http.h"
#include "query.h"
#include "field.h"
#include "mailbox.h"
#include "pagecomponent.h"
#include "httpsession.h"
#include "frontmatter.h"
#include "mimefields.h"
#include "ustring.h"
#include "codec.h"
#include "user.h"
#include "utf.h"


class WebPageData
    : public Garbage
{
public:
    WebPageData()
        : link( 0 ), checker( 0 ), responded( false )
    {}

    Link * link;
    List<PageComponent> components;
    PermissionsChecker * checker;
    bool responded;
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


/*! Adds the PageComponent \a pc to this WebPage. */

void WebPage::addComponent( PageComponent * pc )
{
    d->components.append( pc );
    pc->setPage( this );
}


void WebPage::execute()
{
    if ( d->responded )
        return;

    bool done = true;
    List<PageComponent>::Iterator it( d->components );
    while ( it ) {
        if ( !it->done() ) {
            it->execute();
            done = false;
        }
        ++it;
    }

    if ( !done )
        return;

    List<FrontMatter> frontMatter;

    frontMatter.append( FrontMatter::styleSheet() );

    uint status = 200;
    it = d->components;
    while ( it ) {
        List<FrontMatter>::Iterator f( it->frontMatter() );
        while ( f ) {
            frontMatter.append( f );
            ++f;
        }
        if ( it->status() > status )
            status = it->status();
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
        html.append( "<div class=\"" );
        html.append( it->divClass() );
        html.append( "\">\n" );
        html.append( it->contents() );
        html.append( "\n</div>\n" );
        ++it;
    }

    html.append( "</body>\n" );

    d->link->server()->setStatus( status, "Ok" );
    d->link->server()->respond( "text/html", html );
    d->responded = true;
}



/*! Notes that this WebPage requires \a r on \a m. execute() should
    proceed only if and when permitted() is true.
*/

void WebPage::requireRight( Mailbox * m, Permissions::Right r )
{
    if ( !d->checker )
        d->checker = new PermissionsChecker;

    User * u;
    if ( d->link->server()->session() )
        u = d->link->server()->session()->user();
    if ( d->link->type() == Link::Archive ) {
        u = new User;
        u->setLogin( "anonymous" );
    }

    // XXX: If we need a session, and don't have one, this is where we
    // redirect to the login page.

    Permissions * p = d->checker->permissions( m, u );
    if ( !p )
        p = new Permissions( m, u, this );

    d->checker->require( p, r );
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
    if ( !d->checker )
        return false;
    if ( !d->checker->ready() )
        return false;
    if ( d->checker->allowed() )
        return true;

    d->responded = true;
    d->link->server()->setStatus( 403, "Forbidden" );
    d->link->server()->respond( "text/plain",
                                d->checker->error().simplified() + "\n" );
    return false;
}


class BodypartPageData
    : public Garbage
{
public:
    BodypartPageData()
        : link( 0 ), b( 0 ), c( 0 )
    {}

    Link * link;
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
    d->link = link;
}


void BodypartPage::execute()
{
    if ( !d->b ) {
        requireRight( d->link->mailbox(), Permissions::Read );

        d->b = new Query( "select text, data from bodyparts b join "
                          "part_numbers p on (p.bodypart=b.id) where "
                          "mailbox=$1 and uid=$2 and part=$3", this );
        d->b->bind( 1, d->link->mailbox()->id() );
        d->b->bind( 2, d->link->uid() );
        d->b->bind( 3, d->link->part() );
        d->b->execute();
        d->c = new Query( "select value from header_fields where "
                          "mailbox=$1 and uid=$2 and (part=$3 or part=$4) "
                          "and field=$5 order by part<>$3", this );
        d->c->bind( 1, d->link->mailbox()->id() );
        d->c->bind( 2, d->link->uid() );

        String part( d->link->part() );
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

    String t( "TEXT/PLAIn" );
    r = d->c->nextRow();
    if ( r )
        t = r->getString( "value" );

    String b;
    r = d->b->nextRow();
    // XXX: Invalid part
    if ( r->isNull( "data" ) ) {
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

    d->link->server()->respond( t, b );
}
