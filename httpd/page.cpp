// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "page.h"

#include "utf.h"
#include "link.h"
#include "user.h"
#include "http.h"
#include "mailbox.h"
#include "message.h"
#include "ustring.h"
#include "session.h"
#include "bodypart.h"
#include "allocator.h"
#include "messageset.h"
#include "mimefields.h"
#include "httpsession.h"
#include "addressfield.h"


static String * jsUrl;
static String * cssUrl;

static const char * htmlQuoted( char );
static String htmlQuoted( const String & );
static String address( Message *, HeaderField::Type );


class PageData {
public:
    PageData()
        : type( Page::Error ), state( 0 ),
          link( 0 ), server( 0 ), ready( false ),
          user( 0 ), message( 0 ),
          uid( 0 ), session( 0 ),
          uniq( 0 )
    {}

    Page::Type type;
    uint state;

    Link *link;
    String text, data;
    String ct;
    HTTP *server;
    bool ready;

    String login;
    String passwd;
    User *user;
    Message *message;
    uint uid;
    Session * session;

    uint uniq;
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
    d->ct = "text/html; charset=utf-8";

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
    r.append( "<style>"
              ".hidden{display:none;}"
              ".njshidden{display:none;}"
              ".jsonly{display:none;}"
              ".njsvisible{}"
              "</style>" );
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


/*! Returns the content-type of this page, or a null string if the
    page isn't ready().

*/

String Page::contentType() const
{
    if ( !ready() )
        return "";
    return d->ct;
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


static List<Session> * sessions;


/*! Prepares to display a mailbox.
*/

void Page::mailboxPage()
{
    log( "mailboxPage for " + d->link->mailbox()->name() + " with uidnext " +
         fn( d->link->mailbox()->uidnext() ) );

    if ( !d->session ) {
        if ( !::sessions ) {
            ::sessions = new List<Session>;
            Allocator::addEternal( ::sessions,
                                   "mailbox sessions used via http" );
        }
        List<Session>::Iterator it( *::sessions );
        while ( it && it->mailbox() != d->link->mailbox() )
            ++it;
        d->session = it;
        if ( !d->session ) {
            d->session = new Session( d->link->mailbox(), true );
            ::sessions->append( d->session );
        }
    }

    if ( !d->session->initialised() ) {
        d->session->refresh( this );
        d->uid = 0;
        return;
    }

    if ( d->session->count() == 0 ) {
        d->text = "<p>Mailbox is empty";
        d->ready = true;
    }

    if ( !d->uid ) {
        MessageSet ms;
        ms.add( d->session->uid( 1 ),
                d->session->uid( d->session->count() ) );
        d->session->mailbox()->fetchHeaders( ms, this );
        d->uid = d->session->uid( 1 );
    }

    uint highest = d->session->uid( d->session->count() );

    while ( d->uid < highest ) {
        Message * m = d->session->mailbox()->message( d->uid );
        if ( !m || !m->hasHeaders() )
            return;
        d->uid++;
    }

    String s;
    uint msn = 1;
    while ( msn <= d->session->count() ) {
        uint uid =  d->session->uid( msn );
        Message *m = d->session->mailbox()->message( uid );
        msn++;
        if ( m && !m->header()->fields()->isEmpty() ) {
            s.append( "<div class=messagesummary><div class=header>" );

            HeaderField *hf = m->header()->field( HeaderField::Subject );
            if ( hf ) {
                s.append( "<div class=headerfield name=subject>Subject: " );
                s.append( "<a href=\"" + d->link->string() + "/" +
                          fn( uid ) + "\">" );
                s.append( htmlQuoted( hf->data() ) );
                s.append( "</a></div>" );
            }
            s.append( address( m, HeaderField::From ) );
            s.append( address( m, HeaderField::To ) );
            s.append( address( m, HeaderField::Cc ) );

            s.append( "</div></div>" );

        }
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

/*! This helper turns \a s into HTML. It is public for convenience and
    ease of testing. It should not be called by other classes.
*/

String Page::textPlain( const String & s )
{
    String r;
    r.reserve( s.length() );
    r.append( "<div class=textplain>" );
    uint i = 0;
    bool quoted = false;
    bool newPara = true;
    while ( i < s.length() ) {
        if ( newPara ) {
            if ( s[i] == '>' ) {
                r.append( "\n<p class=quoted>" );
                quoted = true;
            }
            else {
                r.append( "\n<p>" );
                quoted = false;
            }
            newPara = false;
        }

        if ( s[i] == 13 || s[i] == 10 ) {
            uint cr = 0;
            uint lf = 0;
            bool done = false;
            do {
                if ( s[i] == 13 ) {
                    cr++;
                    i++;
                }
                else if ( s[i] == 10 ) {
                    lf++;
                    i++;
                }
                else {
                    done = true;
                }
            } while ( !done );
            if ( i >= s.length() )
                ;
            else if ( cr <= 1 && lf <= 1 )
                r.append( "<br>\n" );
            else
                newPara = true;
        }
        else {
            const char * element = htmlQuoted( s[i] );
            if ( element )
                r.append( element );
            else
                r.append( s[i] );
            i++;
        }
    }
    r.append( "</div>\n" );
    return r;
}


static String unwindStack( StringList & stack, const String & tag )
{
    String r;
    StringList::Iterator it( stack.last() );
    while ( it && tag != *it )
        --it;
    if ( !it )
        return r;
    String s;
    do {
        it = stack.last();
        if ( it ) {
            s = *it;
            stack.take( it );
            if ( s != "p" && s != "body" && s != "script" && s != "style" ) {
                r.append( "</" );
                r.append( s );
                r.append( ">" );
            }
        }
    } while ( it && tag != s );
    return r;
}


static bool visibility( StringList & stack )
{
    StringList::Iterator it( stack );
    while ( it && *it != "body" )
        ++it;
    if ( !it )
        return false;
    while ( it && *it != "style" && *it != "script" )
        ++it;
    if ( it )
        return false;
    return true;
}


/*! This helper turns \a s into plain HTML, without anything that
    might expose the browser to problems (javascript, webbugs, overly
    inventive syntax, that sort of thing).

    It is public for convenience and ease of testing. It should not be
    called by other classes.
*/

String Page::textHtml( const String & s )
{
    String r;
    r.reserve( s.length() );
    r.append( "<div class=texthtml>" );
    StringList stack;
    uint i = 0;
    bool visible = false;
    while ( i < s.length() ) {
        uint j = i;
        while ( j < s.length() && s[j] != '<' )
            j++;
        if ( visible )
            r.append( s.mid( i, j-i ).simplified() );
        i = j;
        if ( s[i] == '<' ) {
            i++;
            j = i;
            while ( j < s.length() && s[j] != ' ' && s[j] != '>' )
                j++;
            String tag = s.mid( i, j-i ).lower();
            i = j;
            String href, htmlclass, src;
            while ( i < s.length() && s[i] != '>' ) {
                while ( j < s.length() && s[j] != '>' && s[j] != '=' )
                    j++;
                String arg = s.mid( i, j-i ).simplified().lower();
                String value;
                i = j;
                if ( s[i] == '=' ) {
                    i++;
                    while ( s[i] == ' ' || s[i] == '\t' ||
                            s[i] == 13 || s[i] == 10 )
                        i++;
                    if ( s[i] == '"' ) {
                        j = i+1;
                        // XXX: isn't this wrong? wasn't there some \"
                        // or whatever?
                        while ( j < s.length() && s[j] != '"' && s[j] != 10 )
                            j++;
                        if ( s[j] == 10 ) {
                            // if we ran off the end of a line, it's
                            // most likely broken input. let's go back
                            // and look for > as well as '>'.
                            j = i+1;
                            while ( j < s.length() &&
                                    s[j] != '"' && s[j] != '>' )
                                j++;
                        }
                        value = s.mid( i, j-i );
                        if ( s[j] == '"' )
                            j++;
                        i = j;
                    }
                    else {
                        j = i+1;
                        while ( j < s.length() &&
                                s[j] != '>' &&
                                s[j] != 10 && s[j] != 13 &&
                                s[j] != ' ' && s[j] != '\t' )
                            j++;
                        value = s.mid( i, j-i );
                    }
                    if ( arg == "href" )
                        href = value;
                    else if ( arg == "class" )
                        htmlclass = value.lower();
                    else if ( arg == "src" )
                        src = value;
                }
            }
            i++;
            if ( tag[0] == '/' ) {
                if ( tag == "/p" ) {
                    // noop
                }
                else if ( tag == "/blockquote" ) {
                    if ( !stack.isEmpty() && *stack.last() == "p" )
                        r.append( unwindStack( stack, "p" ) );
                }
                else if ( tag == "/div" ||
                          tag == "/ul" ||
                          tag == "/ol" ||
                          tag == "/pre" ||
                          tag == "/td" ||
                          tag == "/tr" ||
                          tag == "/table" ||
                          tag == "/script" ||
                          tag == "/style" ||
                          tag == "/body" ) {
                    r.append( unwindStack( stack, tag.mid( 1 ) ) );
                }
            }
            else if ( tag == "blockquote" ) {
                if ( htmlclass == "cite" ) {
                    r.append( unwindStack( stack, "p" ) );
                    stack.append( new String( "p" ) );
                    r.append( "\n<p class=quoted>" );
                }
            }
            else if ( tag == "p" ) {
                r.append( unwindStack( stack, "p" ) );
                stack.append( new String( "p" ) );
                r.append( "\n<p>" );
            }
            else if ( tag == "p" ||
                      tag == "tr" ||
                      tag == "td" ) {
                r.append( unwindStack( stack, tag ) );
                stack.append( tag );
                r.append( "\n<" );
                r.append( tag );
                r.append( ">" );
            }
            else if ( tag == "br" ) {
                r.append( "<br>\n" );
            }
            else if ( tag == "div" ||
                      tag == "ul" ||
                      tag == "ol" ||
                      tag == "li" ||
                      tag == "dl" ||
                      tag == "dt" ||
                      tag == "dd" ||
                      tag == "pre" ||
                      tag == "table" ||
                      tag == "tr" ||
                      tag == "td" ||
                      tag == "th" ) {
                stack.append( new String( tag ) );
                r.append( "\n<" );
                r.append( tag );
                r.append( ">" );
            }
            else if ( tag == "script" ||
                      tag == "style" ||
                      tag == "body" ) {
                stack.append( new String( tag ) );
            }
            else {
                // in all other cases, we skip the tag. maybe we
                // should treat IMG and A specially.
            }
            visible = visibility( stack );
        }
    }
    r.append( unwindStack( stack, "" ) );
    r.append( "</div>\n" );
    return r;
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
        s.append( textPlain( u.fromUnicode( bp->text() ) ) );
        s.append( "</div>" );
    }
    else if ( type == "text/html" ) {
        s.append( "<div class=body>" );
        s.append( textHtml( u.fromUnicode( bp->text() ) ) );
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
        s.append( " <a href=\"" + d->link->string() + "/" +
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
        s.append( htmlQuoted( hf->data() ) );
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
                t.append( "<div class=headerfield" );
                if ( hf->name().boring() ) {
                    t.append( " name=" );
                    t.append( hf->name() );
                }
                t.append( ">" );
                t.append( htmlQuoted( hf->name() ) );
                t.append( ": " );
                t.append( htmlQuoted( hf->data() ) );
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

    d->ct = "text/plain";
    ContentType *ct = bp->header()->contentType();
    if ( ct )
        d->ct = ct->type() + "/" + ct->subtype();

    Utf8Codec u;
    if ( d->ct.startsWith( "text/" ) )
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


static const char * htmlQuoted( char c )
{
    const char * r = 0;
    switch ( c ) {
    case '<':
        r = "&lt;";
        break;
    case '>':
        r = "&gt;";
        break;
    case '&':
        r = "&amp;";
        break;
    default:
        break;
    }
    return r;
}


static String htmlQuoted( const String & s )
{
    String r;
    r.reserve( s.length() );
    uint i = 0;
    while ( i < s.length() ) {
        if ( s[i] == '<' ) {
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
        s.append( htmlQuoted( it->uname() ) );
        s.append( " &lt;" );
        s.append( htmlQuoted( it->localpart() ) );
        s.append( "@" );
        s.append( htmlQuoted( it->domain() ) );
        s.append( "&gt;</span>" );
        ++it;
        if ( it )
            s.append( ", " );
    }

    s.append( "</div>" );
    return s;
}


/*! Returns a string where \a t is wrapped in javascript magic to show
    and hide it on command. \a show and \a hide are the texts to be
    used. If \a v is true, the text is visible if javascript is not
    availble, if \a v is false, the text is hidden in that case.

    At some point in the future, we probably want to have this
    function return an empty string if \a v is false and we somehow
    know the browser does not execute javascript.
*/


String Page::jsToggle( const String &t,
                       bool v,
                       const String &show,
                       const String &hide )
{
    String s;

    String a = "toggle" + fn( ++d->uniq );
    String b = "toggle" + fn( ++d->uniq );

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
