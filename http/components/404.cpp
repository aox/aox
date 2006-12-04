// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "404.h"

#include "frontmatter.h"
#include "link.h"


/*! \class Error404 404.h
    A component that represents a "File Not Found" error.
*/


/*! Creates a 404 response for the specified \a link, for which no other
    handler was found.
*/

Error404::Error404( Link * link )
    : PageComponent( "error" )
{
    addFrontMatter( FrontMatter::title( "File Not Found" ) );
    setContents( "<h1>File Not Found</h1>"
                 "<p>No such file: " + quoted( link->originalURL() ) +
                 "<p>(Additionally, we couldn't find a haiku to process "
                 "the error.)" );
}
