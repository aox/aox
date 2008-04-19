// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "editview.h"

#include "link.h"
#include "htmlform.h"
#include "frontmatter.h"


/*! \class EditView editview.h
    Allows the user to edit a (new or existing) view.
*/

EditView::EditView()
    : PageComponent( "editview" )
{
}


void EditView::execute()
{
    HtmlForm * f = form();
    setContents( f->html() );
}


/*! This private helper function returns a pointer to a form with all
    the fields necessary for view creation. */

HtmlForm * EditView::form() const
{
    Link * l = new Link;
    l->setType( Link::Webmail );
    l->setMagic( true );
    l->setSuffix( Link::AddView );
    HtmlForm * f = new HtmlForm( l->canonical() );
    f->requireField( "view" );
    f->requireField( "source" );
    f->requireField( "selector" );
    f->addField( "addview", "submit", "Add View" );
    return f;
}
