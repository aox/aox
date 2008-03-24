// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "viewlist.h"

#include "frontmatter.h"
#include "httpsession.h"
#include "webpage.h"
#include "user.h"
#include "link.h"
#include "http.h"


class ViewListData
    : public Garbage
{
public:
    ViewListData()
    {}
};


/*! \class ViewList viewlist.h
    Returns a list of views owned by the logged-in user.
*/

ViewList::ViewList()
    : PageComponent( "viewlist" )
{
    addFrontMatter( FrontMatter::title( "Views" ) );
}


void ViewList::execute()
{
    if ( !d ) {
        d = new ViewListData;
        page()->requireUser();
    }

    if ( !page()->permitted() )
        return;

    setContents( "<p>Nothing here yet." );
}
