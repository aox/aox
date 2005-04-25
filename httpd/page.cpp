// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "page.h"

#include "link.h"
#include "user.h"
#include "http.h"
#include "mailbox.h"
#include "message.h"
#include "httpsession.h"


static const char *head =
"<!doctype html public \"-//W3C//DTD HTML 4.01//EN\">\n"
"<html>"
"<head>"
"<title>Webmail</title>"
"<!-- script src=\"http://www.oryx.com/oryx.js\"></script>"
"<link rel=stylesheet type=\"text/css\" href=\"http://www.oryx.com/oryx.css\" -->"
"</head>"
"<body>"
"<div class=\"page\">"
"<div class=\"container\"><div class=\"content\">";

static const char *foot = "</div></div></div></body></html>\n";

#if 0
static String htmlQuoted( const String & s )
{
    String r;
    r.reserve( s.length() );
    uint i = 0;
    while ( i < s.length() ) {
        if ( s[i] > 126 ) {
            r.append( "&#" );
            r.append( fn( s[i] ) );
            r.append( ";" );
        }
        else if ( s[i] == '<' ) {
            r.append( "&lt;" );
        }
        else if ( s[i] == '>' ) {
            r.append( "&gt;" );
        }
        else if ( s[i] == '&' ) {
            r.append( "&amp;" );
        }
        else {
            r.append( s[i] );
        }
        i++;
    }
    return r;
}
#endif


class PageData {
public:
    PageData()
        : type( Page::Error ),
          link( 0 ), uid( 0 ), server( 0 ), ready( false ),
          user( 0 )
    {}

    Page::Type type;

    Link *link;
    String text;
    uint uid;
    HTTP *server;
    bool ready;

    String login;
    String passwd;
    User *user;
};


/*! \class Page page.h

    The Page class is the basic Oryx web page class. It decides what
    needs to be done based on the Link, fetches the necessary data and
    eventually hands out its text().
*/

/*! Constructs a Page for \a link on \a server. */

Page::Page( Link * link, HTTP *server )
    : d( new PageData )
{
    d->link = link;
    d->server = server;

    if ( link->type() == Link::WebmailMessage ||
         link->type() == Link::WebmailMailbox )
    {
        if ( !d->server->session() ||
             !d->server->session()->user() ||
             d->server->session()->expired() )
        {
            d->type = Error;
            d->server->setStatus( 403, "Forbidden" );
            errorPage();
            return;
        }
    }

    switch ( link->type() ) {
    case Link::Webmail:
        {
            String body = d->server->body();
            HttpSession *s = d->server->session();
            if ( s && !s->expired() )
                d->type = MainPage;
            else if ( body.isEmpty() )
                d->type = LoginForm;
            else
                d->type = LoginData;
        }
        break;

    case Link::WebmailMailbox:
        d->type = WebmailMailbox;
        break;

    case Link::WebmailMessage:
        d->type = WebmailMessage;
        break;

    default:
        d->type = Error;
        d->server->setStatus( 404, "File not found" );
        break;
    }
}


void Page::execute()
{
    switch( d->type ) {
    case MainPage:
        mainPage();
        break;

    case LoginForm:
        loginForm();
        break;

    case LoginData:
        loginData();
        break;

    case WebmailMailbox:
        mailboxPage();
        break;

    case WebmailMessage:
        messagePage();
        break;

    case Error:
        errorPage();
        break;
    }

    if ( ready() )
        d->server->process();
}



/*! Returns the HTML text of this page, or an empty string if the text
    is not yet available.
*/

String Page::text() const
{
    if ( d->text.isEmpty() )
        return "";
    return head + d->text + foot;
}


/*! Returns true only if this page is ready to be rendered.
*/

bool Page::ready() const
{
    return d->ready;
}


/*! Prepares to display an error page.
*/

void Page::errorPage()
{
    switch ( d->server->status() ) {
    case 404:
        d->text = "<p>" + d->link->errorMessage();
        break;

    case 403:
        d->text = "<p>You do not have permission to access that page.";
        break;
    }

    d->ready = true;
}


/*! Prepares to display the login form.
*/

void Page::loginForm()
{
    d->ready = true;
    d->text =
        "<form method=post action=\"/\">"
        "Name: <input type=text name=login value=\"\"><br>"
        "Password: <input type=password name=passwd value=\"\"><br>"
        "<input type=submit value=Login>"
        "</form>";
}


/*! ...
*/

void Page::loginData()
{
    if ( !d->user ) {
        String body = d->server->body();

        uint i;
        i = body.find( '&' );
        if ( i > 0 ) {
            String l = body.mid( 0, i );
            String p = body.mid( i+1 );

            if ( l.startsWith( "login=" ) )
                d->login = l.mid( 6 );

            if ( p.startsWith( "passwd=" ) )
                d->passwd = p.mid( 7 );
        }

        if ( d->login.isEmpty() || d->passwd.isEmpty() ) {
            d->type = LoginForm;
            loginForm();
            return;
        }

        d->user = new User;
        d->user->setLogin( d->login );
        d->user->refresh( this );
    }

    if ( d->user->state() == User::Unverified )
        return;

    if ( d->user->state() == User::Nonexistent ||
         d->user->secret() != d->passwd )
    {
        d->ready = true;
        d->text = "<p>You sent us a bad username and password.";
    }
    else {
        HttpSession *s = d->server->session();
        if ( !s || s->user()->login() != d->user->login() ) {
            s = new HttpSession;
            d->server->setSession( s );
        }
        s->setUser( d->user );
        s->refresh();
        d->type = MainPage;
        mainPage();
    }
}


/*! Prepares to display the main page.
*/

void Page::mainPage()
{
    d->ready = true;
    d->text =
        "<div class=top>"
        "<form method=post action=>"
        "<input type=text name=query>"
        "<input type=submit value=search>"
        "</form>"
        "<a href=\"\">Logout</a>"
        "<a href=\"\">Compose</a>"
        "</div>"
        "<div class=middle>"
        "<div class=folders>"
        "<p>Folder list."
        "</div>"
        "<iframe class=content name=content src=\"" +
        fn( d->server->user()->inbox()->id() ) + "/\">"
        "</iframe>"
        "</div>"
        "<div class=bottom>"
        "</div>";
}


/*! Prepares to display a mailbox.
*/

void Page::mailboxPage()
{
    d->ready = true;
    d->text = "<p>La la la.";
}


/*! Prepares to display a single message.
*/

void Page::messagePage()
{
    d->ready = true;
    d->text = "<p>Who the fuck is Alice?";
}
