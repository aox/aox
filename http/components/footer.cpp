// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "footer.h"

#include "configuration.h"


/*! \class Footer footer.h
    This class is used to include some text at the bottom of each page.
    (Should the text be configurable?)
*/

/*! Creates a new Footer component. */

Footer::Footer()
    : PageComponent( "footer" )
{
}


void Footer::execute()
{
    String s( "<hr>\n" );
    s.append( "Archiveopteryx/" );
    s.append( Configuration::compiledIn( Configuration::Version ) );
    s.append( " at " );
    s.append( Configuration::hostname() );
    setContents( s );
}
