// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "loginform.h"

#include "frontmatter.h"
#include "httpsession.h"
#include "webpage.h"
#include "user.h"
#include "link.h"
#include "http.h"


/*! \class LoginForm loginform.h
    Returns a login form.
*/

LoginForm::LoginForm()
    : PageComponent( "loginform" )
{
    addFrontMatter( FrontMatter::title( "Login" ) );
}


void LoginForm::execute()
{
    HttpSession * s = page()->link()->server()->session();

    String login;
    if ( s )
        login = s->user()->login();

    setContents( "<form name=login method=post action=\"" +
                 page()->link()->canonical() + "\">\n"
                 "<label for=login>Name:</label>"
                 "<input type=text name=login value=\"" +
                 quoted( login ) + "\">"
                 "<br>\n"
                 "<label for=passwd>Password:</label>"
                 "<input type=password name=passwd value=\"\">\n"
                 "<br>\n"
                 "<label for=submit>&nbsp;</label>"
                 "<input name=submit type=submit value=Login>\n"
                 "</form>" );
}
