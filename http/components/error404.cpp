// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "error404.h"

#include "frontmatter.h"
#include "link.h"


/*! \class Error404 error404.h
    A component that represents a "File Not Found" error.
*/


/*! Creates a 404 response for the specified \a link, for which no other
    handler was found.
*/

Error404::Error404( Link * link )
    : PageComponent( "error" )
{
    addFrontMatter( FrontMatter::title( "Page Not Found" ) );
    String r( "<h1>Page Not Found</h1>"
              "<p>No such page: " );
    r.append( quoted( link->original() ) );
    r.append( "\n<p>" );
    String c( link->canonical() );
    if ( link->type() == Link::Error || c == link->original() ) {
        r.append( "(Additionally, we couldn't find a haiku to process "
                  "the error.)" );
    }
    else {
        r.append( "Perhaps <a href=\"" );
        r.append( c );
        r.append( "\">" );
        r.append( quoted( c ) );
        r.append( "</a> is the page you want. "
                  "If not, maybe it can help you find the page you want." );
    }
    setContents( r );
    setStatus( 404 );
}
