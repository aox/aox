// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "error301.h"

#include "link.h"
#include "http.h"


/*! \class Error301 error301.h

    The Error301 component contains tet instructing the browser to go
    elsehere. For now it only uses a 301 response, but maybe it should
    also include <meta http> and/or javascript blah. Lots of people
    seem to use belt and bracess, so it can't be entirely pointless.
*/



/*!  Constructs a PageComponent that instructs the WebPage to return a
     301 response and redirect the browser to \a target.
*/

Error301::Error301( Link * target )
    : PageComponent( "redirect" )
{
    String t( target->canonical() );
    setContents( "<h1>Wrong URL</h1>"
                 "<p>The correct URL is <a href=\"" + t + "\">" +
                 quoted( t ) + "</a>.</p>" );
    setStatus( 301 );
    target->server()->addHeader( "Location: " + t );
}
