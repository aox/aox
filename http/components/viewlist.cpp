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

    This component may either be embedded in a page (such as the webmail
    index page), or accessed through its own URL by JavaScript code in a
    previously-rendered page.

    In either case, it returns only a <ul> of views, and assumes that it
    will be used in a context that has already set up the JavaScript one
    needs to make sense of the results.
*/

ViewList::ViewList()
    : PageComponent( "viewlist" )
{
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

    EString s;
    if ( d->q->hasResults() ) {
        s.append( "<ul>\n" );
        while ( d->q->hasResults() ) {
            Row * r = d->q->nextRow();
            s.append( "<li>" );
            s.appendNumber( r->getInt( "id" ) );
            s.append( ": " );
            s.append( r->getEString( "name" ) );
            s.append( " as <code>" );
            s.append( r->getEString( "selector" ) );
            s.append( "</code>\n" );
        }
        s.append( "</ul>" );
    }
    else {
        s = "<p>No views defined.";
    }

    setContents( s );
}
