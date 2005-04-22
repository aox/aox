#include "page.h"

#include "link.h"
#include "user.h"
#include "http.h"
#include "mailbox.h"
#include "message.h"


static const char *head =
"<!doctype html public \"-//W3C//DTD HTML 4.01//EN\">\n"
"<html>"
"<head>"
"<title>Webmail</title>"
"<script src=\"http://www.oryx.com/oryx.js\"></script>"
"<link rel=stylesheet type=\"text/css\" href=\"http://www.oryx.com/oryx.css\">"
"</head>"
"<body onload=\"deframe(); enablejs();\">";

static const char *foot = "</body></html>\n";

static const char *webmailText =
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
"</div>"
"<iframe class=content name=content src=INBOX>"
"</iframe>"
"</div>"
"<div class=bottom>"
"</div>";

static const char *accessControlText =
"Access control";

static const char *noSuchMailbox =
"No such mailbox";

static const char *noSuchMessage =
"No such message";


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


class PageData
{
public:
    PageData()
        : link( 0 ), uid( 0 ), server( 0 )
    {}

    Link *link;
    String text;
    uint uid;
    HTTP *server;
};


/*! \class Page page.h

    The Page class is the basic Oryx web page class. It decides what
    needs to be done based on the Link, fetches the necessary data and
    eventually hands out its text().
*/


/*! Constructs a Page for \a link on \a server.
    The page may not be ready() at once.
*/

Page::Page( Link * link, HTTP *server )
    : d( new PageData )
{
    d->link = link;
    d->server = server;
    switch( link->type() ) {
    case Link::ArchiveMailbox:
    case Link::WebmailMailbox:
        checkAccess();
        fetchMailbox();
        break;
    case Link::Webmail:
        d->text = webmailText;
        break;
    case Link::ArchiveMessage:
    case Link::WebmailMessage:
        checkAccess();
        fetchMessage();
        break;
    case Link::Error:
        d->text = htmlQuoted( link->errorMessage() );
        break;
    }
}


/*! Checks that the user associated with this Page has access to read
    the mailbox, and sets an error if not.

    If this Page isn't associated with a Mailbox, this function is a
    noop.
*/

void Page::checkAccess()
{
    Mailbox * m = d->link->mailbox();
    if ( !m )
        return;

    // this is highly unsatisfying. we need to do ACL stuff very
    // soon. what a pity that the IMAP ACL2 work isn't stable yet.

    Mailbox * home = 0;
    if ( d->server->user() )
        home = d->server->user()->home();

    // test 1. if we have a user, we allow access to any folder in his
    // home directory.
    if ( home && m->name().startsWith( home->name() + "/" ) )
        return;
    // test 2. we allow access to any folder outside /users/.
    if ( !m->name().startsWith( "/users/" ) )
        return;
    // test 3. we allow access to synthetic mailboxes. this is a
    // little dubious.
    if ( m->synthetic() )
        return;

    // nothing passed? then we have to fail the access. we really need
    // ACL. RFC2086, here we come.
    d->text = accessControlText;
}


/*! Fetch the mailbox data and present it. If an error has occured,
    this is a noop.

*/

void Page::fetchMailbox()
{
    if ( !d->text.isEmpty() )
        return;

    Mailbox * m = d->link->mailbox();
    if ( !m ) {
        d->text = noSuchMailbox;
        return;
    }

    
}


/*! Blah.
*/

void Page::fetchMessage()
{
    if ( !d->text.isEmpty() )
        return;
    Mailbox * mb = d->link->mailbox();
    if ( !mb || !d->uid ) {
        d->text = noSuchMessage;
        return;
    }
    Message * m = mb->message( d->uid );
    if ( !m ) {
        d->text = noSuchMessage;
        return;
    }
    if ( !m->hasHeaders() ) {
    }
    if ( !m->hasBodies() ) {
    }
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
