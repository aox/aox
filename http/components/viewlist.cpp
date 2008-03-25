// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "viewlist.h"

#include "frontmatter.h"
#include "httpsession.h"
#include "webpage.h"
#include "query.h"
#include "user.h"
#include "link.h"
#include "http.h"


class ViewListData
    : public Garbage
{
public:
    ViewListData()
        : q( 0 )
    {}

    Query * q;
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

    if ( !d->q ) {
        d->q =
            new Query( "select views.id,name,selector from "
                       "views join mailboxes on (views.view=mailboxes.id) "
                       "where owner=$1 and not deleted", this );
        d->q->bind( 1, page()->link()->server()->user()->id() );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    String s;
    if ( d->q->hasResults() ) {
        s.append( "<ul>\n" );
        while ( d->q->hasResults() ) {
            Row * r = d->q->nextRow();
            s.append( "<li>" );
            s.append( fn( r->getInt( "id" ) ) );
            s.append( ": " );
            s.append( r->getString( "name" ) );
            s.append( " as <code>" );
            s.append( r->getString( "selector" ) );
            s.append( "</code>\n" );
        }
        s.append( "</ul>\n" );
    }
    else {
        s = "<p>No views defined.";
    }

    setContents( s );
}
