// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "webmailindex.h"

#include "frontmatter.h"


/*! \class WebmailIndex webmailindex.h
    Manages the components on the main webmail page.

*/

WebmailIndex::WebmailIndex()
    : PageComponent( "webmailindex" )
{
}


void WebmailIndex::execute()
{
    String s;

    addFrontMatter(
        FrontMatter::script(
            "function switchtab () {\n"
            "    $(\"div.viewlist\").toggle();\n"
            "    $(\"div.editview\").toggle();\n"
            "    $(\"div.mailboxlist\").toggle();\n"
            "    return false;\n"
            "};\n"
            "$(document).ready(function () {\n"
            "  $(\"div.viewlist\").hide();\n"
            "  $(\"div.editview\").hide();\n"
            "  $(\"input#toggleMailboxes\").click(switchtab);\n"
            "  $(\"input#toggleViews\").click(switchtab);\n"
            "});"
        )
    );

    s.append( "<input id=toggleMailboxes type=button value=Mailboxes>" );
    s.append( "<input id=toggleViews type=button value=Views>" );

    setContents( s );
}
