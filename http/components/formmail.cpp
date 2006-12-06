// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "formmail.h"

#include "frontmatter.h"
#include "link.h"


/*! \class FormMail formmail.h
    This pagecomponent is an obligatory huge security hole. (Optionally,
    it also displays a compose form.)
*/

/*! Creates a new FormMail component. */

FormMail::FormMail()
    : PageComponent( "formmail" )
{
    addFrontMatter( FrontMatter::jsToggles() );
}


void FormMail::execute()
{
    Link l;
    l.setType( Link::Webmail );
    l.setMagic( true );
    l.setSuffix( Link::Send );

    String s( "<form method=post action=\"" + l.canonical() + "\">\n"
              "<label for=from>From:</label>\n"
              "<input type=text name=from value=\"\"><br>\n"
              "<label for=to>To:</label>\n"
              "<input type=text name=to value=\"\"><br>\n"
              "<label for=cc>Cc:</label>\n"
              "<input type=text name=cc value=\"\"><br>\n"
              "<label for=subject>Subject:</label>\n"
              "<input type=text name=subject value=\"\"><br>\n"
              "<textarea name=body>\n"
              "</textarea><br>\n"
              "<label for=submit>&nbsp;</label>\n"
              "<input type=submit name=submit value=Send>\n"
              "</form>" );
    setContents( s );
}
