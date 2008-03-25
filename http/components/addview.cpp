// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "addview.h"

#include "frontmatter.h"
#include "httpsession.h"
#include "webpage.h"
#include "query.h"
#include "user.h"
#include "link.h"
#include "http.h"


class AddViewData
    : public Garbage
{
public:
    AddViewData()
        : q( 0 )
    {}

    Query * q;
};


/*! \class AddView addview.h
    Allows the user to create a new view.
*/

AddView::AddView()
    : PageComponent( "addview" )
{
}


void AddView::execute()
{
    if ( !d ) {
        d = new AddViewData;
        page()->requireUser();
    }

    if ( !page()->permitted() )
        return;

    HTTP * server = page()->link()->server();
    UString view( server->parameter( "view" ) );
    UString source( server->parameter( "source" ) );
    UString selector( server->parameter( "selector" ) );

    String form(
        "<form method=post>"
        "<label for=view>Name:</label>"
        "<input type=text name=view value=" + quoted( view ) + "><br>\n"
        "<label for=source>Mailbox:</label>"
        "<input type=text name=source value=" + quoted( source ) + "><br>\n"
        "<label for=selector>Selector:</label>"
        "<input type=text name=selector value=" + quoted( selector ) + "><br>\n"
        "<input type=submit value=\"Create View\">"
        "</form>"
    );

    if ( view.isEmpty() || source.isEmpty() || selector.isEmpty() ) {
        setContents( form );
        return;
    }

    setContents( "OK" );
}
