// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "webpage.h"

#include "pagecomponent.h"
#include "frontmatter.h"
#include "http.h"


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
