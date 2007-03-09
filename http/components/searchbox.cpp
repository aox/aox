// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "searchbox.h"

#include "link.h"
#include "webpage.h"


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
    Link * l = page()->link();
    String * query = l->arguments()->find( "query" );
    String s( "<form>" );
    s.append( "<input type=text name=query value=\"" );
    if ( query )
        s.append( *query );
    s.append( "\"><input type=submit value=Search>" );
    s.append( "</form>" );
    setContents( s );
}
