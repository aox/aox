// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "frontmatter.h"

#include "configuration.h"
#include "pagecomponent.h"


/*! \class FrontMatter frontmatter.h
*/

/*! Returns a link to the stylesheet. */

FrontMatter * FrontMatter::styleSheet()
{
    FrontMatter * fm = new FrontMatter;

    fm->append( "<link rel=stylesheet type=\"text/css\" href=\"" );
    fm->append( Configuration::text( Configuration::WebmailCSS ) );
    fm->append( "\">" );

    return fm;
}


/*! Returns a title element for \a s, which will be HTML quoted. */

FrontMatter * FrontMatter::title( const String & s )
{
    FrontMatter * fm = new FrontMatter;

    fm->append( "<title>" );
    fm->append( PageComponent::quoted( s ) );
    fm->append( "</title>" );

    return fm;
}
