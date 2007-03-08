// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "searchbox.h"


/*! \class SearchBox searchbox.h
    This class merely displays a search box on the page.
*/

/*! Creates a new SearchBox component. */

SearchBox::SearchBox()
    : PageComponent( "searchbox" )
{
}


void SearchBox::execute()
{
    String s( "<form>" );
    s.append( "<input type=text name=query>" );
    s.append( "<input type=submit value=Search>" );
    s.append( "</form>" );
    setContents( s );
}
