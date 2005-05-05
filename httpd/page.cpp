// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "page.h"

#include "utf.h"
#include "link.h"
#include "user.h"
#include "http.h"
#include "mailbox.h"
#include "message.h"
#include "ustring.h"
#include "bodypart.h"
#include "allocator.h"
#include "messageset.h"
#include "mimefields.h"
#include "httpsession.h"
#include "addressfield.h"


static String * jsUrl;
static String * cssUrl;

static String htmlQuoted( const String & );
static String address( Message *, HeaderField::Type );
static String jsToggle( const String &, bool, const String &, const String & );


class PageData {
public:
    PageData()
        : type( Page::Error ), state( 0 ),
          link( 0 ), server( 0 ), ready( false ),
          user( 0 ), message( 0 )
    {}

    Page::Type type;
    uint state;

    Link *link;
    String text, data;
    HTTP *server;
    bool ready;

    String login;
    String passwd;
    User *user;
    Message *message;
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
         link->type() == Link::WebmailMailbox ||
         link->type() == Link::WebmailPart )
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

    case Link::WebmailPart:
        d->type = WebmailPart;
        break;

    case Link::ArchiveMailbox:
        d->type = ArchiveMailbox;
        break;

    case Link::ArchiveMessage:
        d->type = ArchiveMessage;
        break;

    case Link::ArchivePart:
        d->type = ArchivePart;
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

    case WebmailPart:
        webmailPartPage();
        break;

    case ArchiveMailbox:
        archivePage();
        break;

    case ArchiveMessage:
        archiveMessagePage();
        break;

    case ArchivePart:
        archivePartPage();
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
    if ( !d->data.isEmpty() )
        return d->data;

    if ( d->text.isEmpty() )
        return "";

    if ( !cssUrl ) {
        cssUrl = new String;
        *cssUrl = Configuration::text( Configuration::WebmailCSS );
        Allocator::addEternal( cssUrl, "the CSS page webmail uses" );
        jsUrl = new String;
        *jsUrl =Configuration::text( Configuration::WebmailJS );
        if ( jsUrl->isEmpty() )
            jsUrl = 0;
        else
            Allocator::addEternal( jsUrl, "the JS page webmail uses" );
    }

    String r = "<!doctype html public \"-//W3C//DTD HTML 4.01//EN\">\n"
               "<html>"
               "<head>"
               "<title>Webmail</title>";
    if ( jsUrl )
        r.append( "<script src=\"" + *jsUrl + "\"></script>" );
    r.append( "<script src=\"http://localhost:8080/~ams/x.js\"></script>" );
    if ( cssUrl )
        r.append( "<link rel=stylesheet type=\"text/css\" href=\"" +
                  *cssUrl + "\">" );
    r.append( "</head>"
              "<body>"
              "<div class=\"page\">" );
    r.append( d->text );
    r.append( "</div></body></html>" );
    return r;
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
    String e;
    switch ( d->server->status() ) {
    case 404:
        e = "No such page: " + htmlQuoted( d->link->string() );
        break;

    case 403:
        e = "You do not have permission to access that page.";
        break;

    default:
        e = "Unknown, unexpected, mystifying error: " +
            fn( d->server->status() ) +
            "<p>Please report this to info@oryx.com.";
    }

    d->text = "<div class=errorpage>"
              "<h1>Error " + fn( d->server->status() ) + "</h1>"
              "<p>" + e + "</div>";

    d->ready = true;
}


/*! Prepares to display the login form.
*/

void Page::loginForm()
{
    String login = "";
    if ( d->server->session() )
        login = d->server->session()->user()->login();
    if ( !d->login.isEmpty() )
        login = d->login;
    d->ready = true;
    d->text =
        "<div class=loginform>"
        "<form method=post action=\"/\">"
        "<table>"
        "<tr><td>Name:</td>"
        "<td><input type=text name=login value=\"" +
        htmlQuoted( login ) + "\"></td></tr>"
        "<tr><td>Password:</td>"
        "<td><input type=password name=passwd value=\"\"></td></tr>"
        "<tr><td></td><td><input type=submit value=Login></td></tr>"
        "</table>"
        "</div>"
        "</form>";
}


/*! Verifies the login data provided and hands work off to mainPage().
*/

void Page::loginData()
{
    if ( !d->user ) {
        String *login = d->server->parameter( "login" );
        String *passwd = d->server->parameter( "passwd" );
        if ( !login || login->isEmpty() || !passwd ) {
            d->type = LoginForm;
            loginForm();
            return;
        }

        d->login = *login;
        d->passwd = *passwd;

        d->user = new User;
        d->user->setLogin( d->login );
        d->user->refresh( this );
    }

    if ( d->user->state() == User::Unverified )
        return;

    if ( d->user->state() == User::Nonexistent ||
         d->user->secret() != d->passwd )
    {
        loginForm();
        d->text = "<div class=errormessage>"
                  "<p>Login and passwword did not match.";
                  "</div>" + d->text + "";
        d->ready = true;
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
        "<div class=search>"
        "<form method=post action=>"
        "<input type=text name=query>"
        "<input type=submit value=search>"
        "</form>"
        "</div>"
        "<div class=buttons>"
        "<a href=\"\">Logout</a>"
        "<a href=\"\">Compose</a>"
        "</div>"
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
    log( "mailboxPage for " + d->link->mailbox()->name() + " with uidnext " +
         fn( d->link->mailbox()->uidnext() ) );

    if ( d->state == 0 ) {
        MessageSet ms;
        Mailbox *m = d->link->mailbox();
        ms.add( 1, m->uidnext()-1 );
        m->fetchHeaders( ms, this );
        d->message = m->message( ms.largest() );
        d->state = 1;
    }

    if ( !d->message->hasFlags() || !d->message->hasHeaders() )
        return;

    String s;
    uint uid = 1;
    while ( uid < d->message->uid() ) {
        Message *m = d->link->mailbox()->message( uid );
        if ( m && !m->header()->fields()->isEmpty() ) {
            s.append( "<div class=messagesummary><div class=header>" );

            HeaderField *hf = m->header()->field( HeaderField::Subject );
            if ( hf ) {
                s.append( "<div class=headerfield name=subject>Subject: " );
                s.append( "<a href=\"" + d->link->string() + "/" +
                          fn( uid ) + "\">" );
                s.append( htmlQuoted( hf->value() ) );
                s.append( "</a></div>" );
            }
            s.append( address( m, HeaderField::From ) );
            s.append( address( m, HeaderField::To ) );
            s.append( address( m, HeaderField::Cc ) );

            log( "added blah for uid " + fn( uid ) );

            s.append( "</div></div>" );

        }
        uid++;
    }

    d->ready = true;
    d->text = s;
}


/*! Prepares to display a single message.
*/

void Page::messagePage()
{
    if ( !messageReady() )
        return;

    d->ready = true;
    d->text = message( d->message, d->message );
}


/*! Prepares to display an archive mailbox.
*/

void Page::archivePage()
{
    mailboxPage();
}


/*! Prepares to display a single archive message.
*/

void Page::archiveMessagePage()
{
    if ( !messageReady() )
        return;

    d->ready = true;
    d->text = message( d->message, d->message );
}


/*! Returns true if d->message has been fetched from the database, and
    false otherwise.
*/

bool Page::messageReady()
{
    if ( !d->message ) {
        Mailbox *m = d->link->mailbox();
        d->message = m->message( d->link->uid(), true );

        MessageSet ms;
        ms.add( d->link->uid() );
        if ( !d->message->hasFlags() )
            m->fetchFlags( ms, this );
        if ( !d->message->hasBodies() )
            m->fetchBodies( ms, this );
        if ( !d->message->hasHeaders() )
            m->fetchHeaders( ms, this );
    }

    if ( !d->message->hasHeaders() ||
         !d->message->hasBodies() )
        return false;
    return true;
}


/*! Returns an HTML representation of the Bodypart \a bp, which belongs
    to the Message \a first.
*/

String Page::bodypart( Message *first, Bodypart *bp )
{
    String s;
    Utf8Codec u;

    String type = "text/plain";
    ContentType *ct = bp->header()->contentType();
    if ( ct )
        type = ct->type() + "/" + ct->subtype();

    if ( type == "text/plain" ) {
        s.append( "<div class=body>" );
        s.append( htmlQuoted( u.fromUnicode( bp->text() ) ) );
        s.append( "</div>" );
    }
    else if ( type == "text/html" ) {
        s.append( "<div class=body>" );
        s.append( u.fromUnicode( bp->text() ) );
        s.append( "</div>" );
    }
    else if ( type == "message/rfc822" ) {
        s.append( "<div class=body>" );
        s.append( message( first, bp->rfc822() ) );
        s.append( "</div>" );
    }
    else if ( type.startsWith( "image/" ) ) {
        s.append( "<div class=image>" );
        s.append( "<a href=\"" + d->link->string() + "/" +
                  first->partNumber( bp ) + "\">" );
        s.append( "<img src=\"" + d->link->string() + "/" +
                  first->partNumber( bp ) + "\">" );
        s.append( "</a></div>" );
    }
    else if ( type.startsWith( "multipart/" ) ) {
        s.append( "<div class=multipart>" );
        List< Bodypart >::Iterator it( bp->children() );
        while ( it ) {
            s.append( bodypart( first, it ) );
            ++it;
        }
        s.append( "</div>" );
    }
    else {
        s.append( "<div class=unknown>" );
        s.append( "Unknown content type: " );
        s.append( type );
        s.append( "<a href=\"" + d->link->string() + "/" +
                  first->partNumber( bp ) + "\">" );
        s.append( "Save" );
        s.append( "</a>" );
        s.append( " (size " );
        s.append( String::humanNumber( bp->numBytes() ) );
        s.append( ")</div>" );
    }

    s.append( "</div>" );
    return s;
}


/*! Returns an HTML representation of the Message \a m, which belongs to
    the Message \a first.
*/

String Page::message( Message *first, Message *m )
{
    String s, t;
    HeaderField *hf;

    s.append( "<div class=message><div class=header>" );

    hf = m->header()->field( HeaderField::Subject );
    if ( hf ) {
        s.append( "<div class=headerfield name=subject>Subject: " );
        s.append( hf->value() );
        s.append( "</div>" );
    }
    s.append( address( m, HeaderField::From ) );
    s.append( address( m, HeaderField::To ) );
    s.append( address( m, HeaderField::Cc ) );

    List< HeaderField >::Iterator it( m->header()->fields() );
    while ( it ) {
        hf = it;

        if ( hf->type() != HeaderField::Subject &&
             hf->type() != HeaderField::From &&
             hf->type() != HeaderField::To &&
             hf->type() != HeaderField::Cc )
        {
            if ( hf->type() <= HeaderField::LastAddressField ) {
                t.append( address( m, hf->type() ) );
            }
            else {
                t.append( "<div class=headerfield name=" + hf->name() + ">" );
                t.append( hf->name() + ": " + hf->value() );
                t.append( "</div>" );
            }
        }

        ++it;
    }
    s.append( jsToggle( t, false, "Show full header", "Hide full header" ) );

    s.append( "</div>" );

    List< Bodypart >::Iterator jt( m->children() );
    while ( jt ) {
        s.append( bodypart( first, jt ) );
        ++jt;
    }

    return s;
}


/*! Prepares to display a single bodypart from the requested message.
*/

void Page::webmailPartPage()
{
    if ( !messageReady() )
        return;

    Bodypart *bp = d->message->bodypart( d->link->part(), false );
    if ( !bp ) {
        d->type = Error;
        d->server->setStatus( 404, "File not found" );
        errorPage();
        return;
    }

    String type = "text/plain";
    ContentType *ct = bp->header()->contentType();
    if ( ct )
        type = ct->type() + "/" + ct->subtype();

    d->server->addHeader( "Content-Type: " + type );

    Utf8Codec u;
    if ( type.startsWith( "text/" ) )
        d->data = u.fromUnicode( bp->text() );
    else
        d->data = bp->data();
    d->ready = true;
}


/*! Prepares to display a single bodypart from the requested archive
    message. This function currently just punts to webmailPartPage()
    above.
*/

void Page::archivePartPage()
{
    webmailPartPage();
}


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


static String address( Message *m, HeaderField::Type t )
{
    String s;

    AddressField *af = m->header()->addressField( t );
    if ( !af )
        return s;

    s.append( "<div class=headerfield name=" + af->name().lower() +">" );
    s.append( af->name() );
    s.append( ": " );

    List< Address >::Iterator it( af->addresses() );
    while ( it ) {
        s.append( "<span class=address>" );
        s.append( htmlQuoted( it->toString() ) );
        s.append( "</span>" );
        ++it;
        if ( it )
            s.append( ", " );
    }

    s.append( "</div>" );
    return s;
}


static uint el = 0;
static String jsToggle( const String &t,
                        bool v,
                        const String &show,
                        const String &hide )
{
    String s;

    String a = "toggle" + fn( el++ );
    String b = fn( el++ );

    if ( v )
        s.append( "<div class=njsvisible id=" + a + ">" );
    else
        s.append( "<div class=njshidden id=" + a + ">" );
    s.append( t );
    s.append( "<div class=jsonly>" );
    s.append( "<a onclick=\"toggleElement('" + b + "', '" + a + "')\">" );
    s.append( hide );
    s.append( "</a></div></div>" );

    s.append( "<div class=jsonly id=" + b + ">" );
    s.append( "<a onclick=\"toggleElement('" + a + "', '" + b + "')\">" );
    s.append( show );
    s.append( "</a></div>" );

    return s;
}
