// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "webpage.h"

#include "http.h"
#include "field.h"
#include "mailbox.h"
#include "pagecomponent.h"
#include "frontmatter.h"
#include "query.h"
#include "link.h"


class WebPageData
    : public Garbage
{
public:
    WebPageData()
        : owner( 0 )
    {}

    HTTP * owner;
    List<PageComponent> components;
};


/*! \class WebPage webpage.h

    A WebPage is a collection of PageComponents, each with some relevant
    FrontMatter objects. It waits for all its components to assemble
    their contents, and then composes the response.
*/

/*! Creates a new WebPage owned by the HTTP server \a owner. */

WebPage::WebPage( HTTP * owner )
    : d( new WebPageData )
{
    d->owner = owner;
}


/*! Adds the PageComponent \a pc to this WebPage. */

void WebPage::addComponent( PageComponent * pc )
{
    d->components.append( pc );
    pc->setPage( this );
}


void WebPage::execute()
{
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

    d->owner->setStatus( status, "Ok" );
    d->owner->respond( "text/html", html );
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
    ...
*/

/*! ... */

BodypartPage::BodypartPage( Link * link )
    : WebPage( link->server() ),
      d( new BodypartPageData )
{
    d->link = link;
}


void BodypartPage::execute()
{
    if ( !d->b ) {
        // XXX: Permissions
        d->b = new Query( "select text, data from bodyparts b join "
                          "part_numbers p on (p.bodypart=b.id) where "
                          "mailbox=$1 and uid=$2 and part=$3", this );
        d->b->bind( 1, d->link->mailbox()->id() );
        d->b->bind( 2, d->link->uid() );
        d->b->bind( 3, d->link->part() );
        d->b->execute();
        d->c = new Query( "select value from header_fields where "
                          "mailbox=$1 and uid=$2 and part=$3 and "
                          "field=$4", this );
        d->c->bind( 1, d->link->mailbox()->id() );
        d->c->bind( 2, d->link->uid() );
        d->c->bind( 3, d->link->part() );
        d->c->bind( 4, HeaderField::ContentType );
        d->c->execute();
    }

    if ( !d->b->done() || !d->c->done() )
        return;

    Row * r;

    String ct( "text/plain" );
    r = d->c->nextRow();
    if ( r )
        ct = r->getString( "value" );

    String b;
    r = d->b->nextRow();
    // XXX: Invalid part
    if ( r->isNull( "data" ) )
        // XXX: charset
        b = r->getString( "text" );
    else
        b = r->getString( "data" );

    d->link->server()->respond( ct, b );
}
