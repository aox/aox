// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "page.h"

#include "utf.h"
#include "dict.h"
#include "link.h"
#include "list.h"
#include "user.h"
#include "http.h"
#include "query.h"
#include "mailbox.h"
#include "message.h"
#include "ustring.h"
#include "bodypart.h"
#include "allocator.h"
#include "messageset.h"
#include "mimefields.h"
#include "httpsession.h"
#include "mailboxview.h"
#include "permissions.h"
#include "addressfield.h"


static String * jsUrl;
static String * cssUrl;

static const char * htmlQuoted( char );
static String htmlQuoted( const String & );
static String address( Address * );
static String addressField( Message *, HeaderField::Type );


class PageData
    : public Garbage
{
public:
    PageData()
        : type( Page::Error ), state( 0 ),
          link( 0 ), server( 0 ), ready( false ),
          user( 0 ),
          searchQuery( 0 ),
          mailboxView( 0 ),
          permissions( 0 ),
          uniq( 0 )
    {}

    Page::Type type;
    uint state;

    Link * link;
    String text, data;
    String ct;
    HTTP * server;
    bool ready;

    String login;
    String passwd;
    User * user;
    Query * searchQuery;
    MailboxView * mailboxView;
    Permissions * permissions;

    uint uniq;
    uint msn;
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
         link->type() == Link::WebmailPart ||
         link->type() == Link::WebmailSearch )
    {
        if ( !d->server->session() ||
             !d->server->session()->user() )
        {
            d->type = Error;
            d->server->setStatus( 403, "Forbidden" );
            errorPage();
            return;
        }
        else if ( d->server->session()->expired() ) {
            d->server->setStatus( 302, "Session Expired" );
            d->server->addHeader( "Location: /" );
            d->text = "<div class=errorpage>"
                      "<h1>Session Timeout</h1>"
                      "<p>Please <a href=\"/\">log in again</a></div>\n";
            d->ready = true;
            return;
        }
        if ( d->link->mailbox() )
            d->permissions
                = new Permissions( d->link->mailbox(),
                                   d->server->user(),
                                   this );
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

    case Link::WebmailSearch:
        d->type = WebmailSearch;
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

    case Link::ArchiveSearch:
        d->type = ArchiveSearch;
        break;

    case Link::Favicon:
        d->type = Favicon;
        break;

    case Link::Logout:
        d->type = Logout;
        break;

    case Link::Compose:
        d->type = Compose;
        break;

    default:
        d->type = Error;
        d->server->setStatus( 404, "File not found" );
        break;
    }
}


void Page::execute()
{
    // if we're ready already, there's no point in doing anything, and
    // it might be harmful, if the HTTP has sent the response already.
    if ( d->ready )
        return;

    if ( d->permissions && !d->permissions->ready() )
        return;

    if ( d->permissions && !d->permissions->allowed( Permissions::Read ) ) {
        d->type = Error;
        d->server->setStatus( 403, "Forbidden" );
    }

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

    case WebmailSearch:
        webmailSearchPage();
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

    case ArchiveSearch:
        archiveSearchPage();
        break;

    case Favicon:
        favicon();
        break;

    case Logout:
        logoutPage();
        break;

    case Compose:
        composePage();
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
               "<title>";
    r.append( htmlQuoted( Configuration::text( Configuration::Hostname ) ) );
    r.append( " webmail</title>\n" );
    r.append( "<style type=\"text/css\">\n" );
    if ( cssUrl )
        r.append( "@import url(\"" + *cssUrl + "\");\n" );
    r.append( ".jsonly{display:none;}\n" // visible if js, inv. otherwise
              ".njsvisible{}\n" // hidden if js, visible if not
              ".hidden{display:none;}\n" // invisible (set by js code)
              ".njshidden{display:none;}\n" // invisible (showable by js code)
              " </style>\n" );
    // change the first two rules if the browser supports javascript
    r.append( "<script language=javascript type=\"text/javascript\">\n"
              "var toggledToJs=false;\n"
              "function useJS(){\n"
              "if(toggledToJs)"
              "return;\n"
              "var r=new Array;\n"
              "if(document.styleSheets[0].cssRules)"
              "r=document.styleSheets[0].cssRules;\n"
              "else if(document.styleSheets[0].rules)"
              "r=document.styleSheets[0].rules;\n"
              "else "
              "return;\n"
              "var i=0;\n"
              "if(r[1].style.display=='none')"
              "i=1;\n"
              "r[i].style.display='';\n"
              "r[i+1].style.display='none';\n"
              "toggledToJs=true\n"
              "}\n"
              // change the css to use the javascript version at once
              // for browsers that can...
              "useJS();\n"
              // and later for safari and whatever else
              "window.onload = 'useJS();';\n"
              // a function to show an element
              "function reveal(e){\n"
              "document.getElementById(e).className='visible'"
              "}\n"
              // a function to hide an element
              "function hide(e){\n"
              "document.getElementById(e).className='hidden'"
              "}\n"
              // an array to record what we're showing
              "var hiddenIds=new Array;\n"
              // a function to expand/collapse a message
              "function expandCollapse(i,a,b,c){\n"
              "if(hiddenIds[i]){\n"
              "reveal(a);\n"
              "reveal(b);\n"
              "hide(c);\n"
              "hiddenIds[i]=false\n"
              "}else{\n"
              "hide(a);\n"
              "hide(b);\n"
              "reveal(c);\n"
              "hiddenIds[i]=true\n"
              "}\n"
              "}\n" );
    r.append( "</script>\n" );
    if ( jsUrl )
        r.append( "<script src=\"" + *jsUrl + "\"></script>\n" );
    r.append( "</head>\n"
              "<body>"
              "<div class=\"page\">\n" );
    r.append( d->text );
    r.append( "</div>\n"
              "</body></html>\n" );
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
        loginForm();
        e = "You do not have permission to access that page." + d->text;
        break;

    default:
        e = "Unknown, unexpected, mystifying error: " +
            fn( d->server->status() ) +
            "<p>Please report this to info@oryx.com.";
    }

    d->text = "<div class=errorpage>"
              "<h1>Error " + fn( d->server->status() ) + "</h1>"
              "<p>" + e + "</div>\n";

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
        "<div class=loginform>\n"
        "<form name=login method=post action=\"/\">\n"
        "<label for=login>Name:</label>"
        "<input type=text name=login value=\"" +
        htmlQuoted( login ) + "\">"
        "<br>\n"
        "<label for=passwd>Password:</label>"
        "<input type=password name=passwd value=\"\">\n"
        "<br>\n"
        "<label for=submit>&nbsp;</label>"
        "<input name=submit type=submit value=Login>\n"
        "</div>"
        "</form>\n";
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
                  "<p>Login and password did not match.";
                  "</div>\n" + d->text + "";
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


static String mailboxDescriptor( Mailbox * m, uint prefixLength = 0 )
{
    String r;
    String n( m->name().mid( prefixLength ) );
    if ( !n.isEmpty() ) {
        r.append( "<li class=mailboxname>" );
        bool link = true;
        if ( m->synthetic() || m->deleted() )
            link = false;
        if ( link ) {
            r.append( "<a href=\"/" );
            r.append( fn( m->id() ) );
            r.append( "\">" );
        }
        r.append( htmlQuoted( m->name().mid( prefixLength ) ) );
        if ( link )
            r.append( "</a>" );
        r.append( "\n" );
    }
    List<Mailbox> * c = m->children();
    if ( c && !c->isEmpty() ) {
        String sub;
        List<Mailbox>::Iterator i( c->first() );
        uint l = m->name().length() + 1;
        while ( i ) {
            if ( !i->deleted() )
                sub.append( mailboxDescriptor( i, l ) );
            ++i;
        }
        if ( !sub.isEmpty() ) {
            r.append( "<ul class=mailboxlist>\n" );
            r.append( sub );
            r.append( "</ul>\n" );
        }
    }
    return r;
}


/*! Prepares to display the main page.
*/

void Page::mainPage()
{
    // XXX HACK to work around the mainpage/inbox dualism - two URLs
    // map to the same result. think about a more proper approach.
    d->link = new Link( "/" + fn( d->server->user()->inbox()->id() ) );
    d->type = WebmailMailbox;
    mailboxPage();
}


/*! Returns the string necessary to display \a m, without any
    extraneous surrounding text (search buttons etc). mainPage(),
    mailboxPage() and archivePage() all use this and supplement it
    with extras of their choosing.

    If mailbox() cannot return a finished result, it returns an empty
    string and expects to be called again. In this case it arranges
    for execute() to be called again.
*/

String Page::mailbox( Mailbox * m )
{
    MailboxView * mv = MailboxView::find( m );
    mv->refresh( this );
    if ( !mv->ready() )
        return "";

    if ( mv->count() == 0 ) {
        d->text = "<p>Mailbox is empty";
        d->ready = true;
    }

    String s;
    List<MailboxView::Thread>::Iterator it( mv->allThreads() );
    while ( it ) {
        MailboxView::Thread * t = it;
        ++it;
        Message * m = t->message( 0 );
        String url( d->link->string() );
        if ( !url.endsWith( "/" ) )
            url.append( "/" );
        url.append( fn( t->uid( 0 ) ) );

        HeaderField * hf = m->header()->field( HeaderField::Subject );
        String subject;
        if ( hf )
            subject = hf->data().simplified();
        if ( subject.isEmpty() )
            subject = "(No Subject)";
        s.append( "<div class=thread>\n"
                  "<div class=headerfield>Subject: " );
        s.append( htmlQuoted( subject ) );
        s.append( "</div>\n" ); // subject

        s.append( "<div class=threadcontributors>\n" );
        s.append( "<div class=headerfield>From:\n" );
        uint i = 0;
        while ( i < t->messages() ) {
            m = t->message( i );
            s.append( "<a href=\"" );
            s.append( url );
            if ( i > 0 ) {
                s.append( "#" );
                s.append( fn( t->uid( i ) ) );
            }
            s.append( "\">" );
            AddressField * af
                = m->header()->addressField( HeaderField::From );
            if ( af ) {
                List< Address >::Iterator it( af->addresses() );
                while ( it ) {
                    s.append( address( it ) );
                    ++it;
                    if ( it )
                        s.append( ", " );
                }
            }
            s.append( "</a>" );
            i++;
            if ( i < t->messages() )
                s.append( "," );
            s.append( "\n" );
        }
        s.append( "</div>\n" // headerfield
                  "</div>\n" // threadcontributors
                  "</div>\n" ); // thread
    }

    return s;
}


/*! Prepares to display a mailbox.
*/

void Page::mailboxPage()
{
    String s( mailbox( d->link->mailbox() ) );
    if ( s.isEmpty() )
        return;

    d->text =
        "<div class=page>\n" +
        leftContent() +
        "<div class=formeriframe>\n" + s + "</div>\n"
        "</div>\n"
        ;

    d->ready = true;
}


/*! Prepares to display a single message.

    Misnamed. Displays an entire thread, starting with a message. This
    is an EVIL EVIL HACK. We need a new class modelling a, uh, session
    for a session.
*/

void Page::messagePage()
{
    if ( !d->mailboxView )
        d->mailboxView = MailboxView::find( d->link->mailbox() );

    d->mailboxView->refresh( this );
    if ( !d->mailboxView->ready() )
        return;

    MailboxView::Thread * t = d->mailboxView->thread( d->link->uid() );

    MessageSet s;
    uint n = 0;
    while ( n < t->messages() ) {
        if ( !t->message( n )->hasBodies() )
            s.add( t->uid( n ) );
        n++;
    }

    if ( !s.isEmpty() ) {
//        d->mailboxView->mailbox()->fetchBodies( s, this );
        return;
    }

    d->text = leftContent();
    d->text.append( "<div class=formeriframe>\n" );

    n = 0;
    while ( n < t->messages() ) {
        Message * m = t->message( n );
        d->text.append( "<a name=\"" );
        d->text.append( fn( t->uid( n ) ) );
        d->text.append( "\"></a>\n"
                        "<div class=aboutmessage>"
                        "Message " );
        d->text.append( fn( n+1 ) );
        d->text.append( " of " );
        d->text.append( fn( t->messages() ) );
        d->text.append( "</div>\n" );
        d->text.append( message( m, t->uid( n ), m ) ); // ->uid() twice: slow
        n++;
    }

    d->text.append( "</div>\n" );

    d->ready = true;
}


/*! Prepares to display an archive mailbox.
*/

void Page::archivePage()
{
    String s( mailbox( d->link->mailbox() ) );
    if ( s.isEmpty() )
        return;

    d->text = s;
    d->ready = true;
}


/*! Prepares to display a single archive message.
*/

void Page::archiveMessagePage()
{
    messagePage();
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
        else if ( s[i] == 8 && r.length() > 0 &&
                  r[r.length()-1] != '>' &&
                  r[r.length()-1] != ';' ) {
            r.truncate( r.length()-1 );
            i++;
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
                    else
                        r.append( unwindStack( stack, "blockquote" ) );
                }
                else if ( tag == "/div" ||
                          tag == "/i" ||
                          tag == "/b" ||
                          tag == "/u" ||
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
                else {
                    stack.append( new String( "blockquote" ) );
                    r.append( "\n<blockquote>" );
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
                      tag == "i" ||
                      tag == "b" ||
                      tag == "u" ||
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
    to the Message \a first. \a first is assumed to have UID \a uid.
*/

String Page::bodypart( Message *first, uint uid, Bodypart *bp )
{
    String s;
    Utf8Codec u;

    Link l( d->link, d->link->mailbox(), uid, first->partNumber( bp ) );

    String type = "text/plain";
    ContentType *ct = bp->header()->contentType();
    if ( ct )
        type = ct->type() + "/" + ct->subtype();

    if ( type == "text/plain" ) {
        s.append( "<div class=body>\n" );
        s.append( textPlain( u.fromUnicode( bp->text() ) ) );
        s.append( "</div>\n" );
    }
    else if ( type == "text/html" ) {
        s.append( "<div class=body>\n" );
        s.append( textHtml( u.fromUnicode( bp->text() ) ) );
        s.append( "</div>\n" );
    }
    else if ( type == "message/rfc822" ) {
        s.append( "<div class=body>\n" );
        s.append( message( first, uid, bp->message() ) );
        s.append( "</div>\n" );
    }
    else if ( type.startsWith( "image/" ) ) {
        s.append( "<div class=image>" );
        s.append( "<a href=\"" + l.string() + "\">" );
        s.append( "<img src=\"" + l.string() + "\">" );
        s.append( "</a></div>\n" );
    }
    else if ( type.startsWith( "multipart/" ) ) {
        s.append( "<div class=multipart>\n" );
        List< Bodypart >::Iterator it( bp->children() );
        while ( it ) {
            s.append( bodypart( first, uid, it ) );
            ++it;
        }
        s.append( "</div>\n" );
    }
    else {
        s.append( "<div class=unknown>\n" );

        s.append( "<p>Unknown content type: " );
        s.append( type );
        s.append( "\n" );
        s.append( "<p><a href=\"" + l.string() + "\">" );
        s.append( "Save" );

        String fn;
        ContentDisposition * cd = bp->header()->contentDisposition();
        if ( cd )
            fn = cd->parameter( "filename" );
        if ( ct && fn.isEmpty() )
            fn = ct->parameter( "filename" );
        if ( !fn.isEmpty() ) {
            // XXX i18n unfriendly; enforces "verb object" order
            s.append( " " );
            s.append( htmlQuoted( fn ) );
        }

        s.append( "</a>" );
        s.append( " (size " );
        s.append( String::humanNumber( bp->numBytes() ) );
        s.append( ")</div>\n" );
    }

    return s;
}





/*! Returns an HTML representation of the Message \a m, which has \a
    uid and belongs to the Message \a first.
*/

String Page::message( Message *first, uint uid, Message *m )
{
    bool topLevel = false;
    if ( first == m )
        topLevel = true;
    String optionalHeader = "toggle" + fn( ++d->uniq );
    String fullBody = "toggle" + fn( ++d->uniq );
    String summaryBody = "toggle" + fn( ++d->uniq );

    String s, t;
    HeaderField *hf;

    s.append( "<div class=message>\n"
              "<div class=header>\n" );

    if ( topLevel ) {
        s.append( "<a onclick=\"expandCollapse(" );
        s.append( fn( d->msn++ ) );
        s.append( ",'" );
        s.append( optionalHeader );
        s.append( "','" );
        s.append( fullBody );
        s.append( "','" );
        s.append( summaryBody );
        s.append( "')\">\n" );
    }
    s.append( addressField( m, HeaderField::From ) );
    hf = m->header()->field( HeaderField::Subject );
    if ( hf ) {
        s.append( "<div class=headerfield>Subject: " );
        s.append( htmlQuoted( hf->data() ) );
        s.append( "</div>\n" );
    }
    s.append( addressField( m, HeaderField::To ) );
    if ( topLevel ) {
        s.append( "<div id=" + optionalHeader + ">\n" );
        s.append( "</a>\n" );
    }
    s.append( addressField( m, HeaderField::Cc ) );

    List< HeaderField >::Iterator it( m->header()->fields() );
    while ( it ) {
        hf = it;
        ++it;

        if ( hf->type() != HeaderField::Subject &&
             hf->type() != HeaderField::From &&
             hf->type() != HeaderField::To &&
             hf->type() != HeaderField::Cc )
        {
            if ( hf->type() <= HeaderField::LastAddressField ) {
                t.append( addressField( m, hf->type() ) );
            }
            else {
                t.append( "<div class=headerfield>" );
                t.append( htmlQuoted( hf->name() ) );
                t.append( ": " );
                t.append( htmlQuoted( hf->data().simplified() ) );
                t.append( "</div>\n" );
            }
        }

    }
    s.append( jsToggle( t, false,
                        "Show full header", "Hide full header" ) );

    if ( topLevel )
        s.append( "</div>\n" ); // optionalHeader
    s.append( "</div>\n" ); // header

    if ( topLevel ) {
        s.append( "<div class=njshidden id=" );
        s.append( summaryBody );
        s.append( ">\n" );
        s.append( twoLines( first ) );
        s.append( "</div>\n" ); // jsonly summaryBody
        s.append( "<div id=" );
        s.append( fullBody );
        s.append( ">" );
    }

    List< Bodypart >::Iterator jt( m->children() );
    while ( jt ) {
        s.append( bodypart( first, uid, jt ) );
        ++jt;
    }

    if ( topLevel )
        s.append( "</div>\n" ); // fullBody

    s.append( "</div>\n" ); // message

    return s;
}


/*! Prepares to display a single bodypart from the requested message.

    If the bodypart isn't an image, this sends a Content-Disposition
    suggesting that the browser should download the page instead of
    displaying it.
*/

void Page::webmailPartPage()
{
    Message * m = 0;
    if ( d->link->mailbox() )
//        m = d->link->mailbox()->message( d->link->uid(), false )
        ;
    if ( !m || !m->hasBodies() || !m->hasHeaders() ) {
        MessageSet s;
        s.add( d->link->uid() );
//        d->mailboxView->mailbox()->fetchHeaders( s, this );
//        d->mailboxView->mailbox()->fetchBodies( s, this );
        return;
    }

    Bodypart *bp = m->bodypart( d->link->part(), false );
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

    String fn;
    ContentDisposition * cd = bp->header()->contentDisposition();
    if ( cd )
        fn = cd->parameter( "filename" );
    if ( ct && fn.isEmpty() )
        fn = ct->parameter( "filename" );

    if ( !fn.isEmpty() || !d->ct.startsWith( "image/" ) ) {
        if ( fn.isEmpty() )
            d->server->addHeader( "Content-Disposition: attachment; "
                                  "filename=attachment");
        else
            d->server->addHeader( "Content-Disposition: attachment; "
                                  "filename=" + fn.quoted() );
    }

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


static String address( Address * a )
{
    String s( "<span class=address>" );
    s.append( htmlQuoted( a->uname() ) );
    s.append( " &lt;" );
    s.append( htmlQuoted( a->localpart() ) );
    s.append( "@" );
    s.append( htmlQuoted( a->domain() ) );
    s.append( "&gt;</span>" );

    return s;
}



static String addressField( Message *m, HeaderField::Type t )
{
    String s;

    AddressField *af = m->header()->addressField( t );
    if ( !af )
        return s;

    s.append( "<div class=headerfield>" );
    s.append( af->name() );
    s.append( ": " );

    List< Address >::Iterator it( af->addresses() );
    while ( it ) {
        s.append( address( it ) );
        ++it;
        if ( it )
            s.append( ", " );
    }

    s.append( "</div>\n" );
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
        s.append( "<div class=njsvisible id=" + a + ">\n" );
    else
        s.append( "<div class=njshidden id=" + a + ">\n" );
    s.append( t );
    s.append( "<div class=jsonly>" );
    s.append( "<a onclick=\"reveal('" + b + "');hide('" + a + "')\">" );
    s.append( "<a onclick=\"reveal('" + b + "');hide('" + a + "')\">" );
    s.append( hide );
    s.append( "</a></div>\n</div>\n" );

    s.append( "<div class=jsonly id=" + b + ">" );
    s.append( "<a onclick=\"reveal('" + a + "')hide('" + b + "')\">" );
    s.append( show );
    s.append( "</a></div>\n" );

    return s;
}


/*! Returns the icon for this webmail service. This is a 302 redirect
    to an admin-configurable URL, or the Oryx logo by default.
*/

void Page::favicon()
{
    String url( Configuration::text( Configuration::FaviconURL ) );
    if ( url.isEmpty() )
        url = "http://www.oryx.com/favicon.ico";
    d->server->setStatus( 302, "look over there!" );
    d->server->addHeader( "Location: " + url );
    d->ready = true;
}


/*! Returns text suitable for composing an original message. This is
    really, really primitive.

    Should we demand javascript support for things like attaching more
    than one file?
*/

void Page::composePage()
{
    d->ready = true;
    d->text = "Placeholder";
}


/*! Logs the user out and returns some text to that effect. */

void Page::logoutPage()
{
    loginForm();
    if ( d->server->session() )
        d->server->session()->expireNow();
    d->text = "<h1>Logged out</h1>\n"
              "<p>To log in again, fill in the form below.\n" +
              d->text;
}


/*! Performs a search and/or retrieves a cached result. Presents the
    whole thing.

    The search and presentation need to be divided.
*/

void Page::webmailSearchPage()
{
    if ( !d->mailboxView ) {
        d->mailboxView = MailboxView::find( d->link->mailbox() );
        d->mailboxView->refresh( this );
    }
    if ( !d->searchQuery ) {
        String * terms = d->server->parameter( "query" );
        if ( !terms || terms->simplified().isEmpty() ) {
            // XXX: give a little more sensible error message. or
            // better yet, a "how to search" page.
            d->type = Error;
            errorPage();
        }
        // XXX: check that *terms not only contains @, but that the
        // domain looks more or less reasonable.
        if ( terms->find( '@' ) > 0 ) {
            d->searchQuery
                = new Query( "select uid from address_fields af "
                             "join addresses a "
                             "on (af.address=a.id)"
                             "where af.mailbox=$1 and "
                             "lower(a.localpart)=$2 and "
                             "lower(a.domain)=$3",
                             this );
            String localpart = terms->mid( 0, terms->find( '@' ) ).lower();
            String domain = terms->mid( 1 + terms->find( '@' ) ).lower();
            d->searchQuery->bind( 1, d->link->mailbox()->id() );
            d->searchQuery->bind( 2, localpart );
            d->searchQuery->bind( 3, domain );
        }
        else {
            String s;
            String arg;

            String db = Database::type();
            if ( !db.endsWith( "+tsearch2" ) ) {
                s = "select uid from header_fields where mailbox=$1 "
                    "and field=20 and value ilike '%'||$2||'%' "
                    "union "
                    "select pn.uid from part_numbers pn, bodyparts b "
                    "where pn.mailbox=$1 and pn.bodypart=b.id and "
                    "b.text ilike '%'||$2||'%'";
                arg = *terms;
            }
            else {
                s = "select uid from header_fields where mailbox=$1 "
                    "and subjectidx @@ to_tsquery('default', $2) "
                    "union "
                    "select pn.uid from part_numbers pn, bodyparts b "
                    "where pn.mailbox=$1 and pn.bodypart=b.id and "
                    "b.ftidx @@ to_tsquery('default', $3)";

                uint n = 0;
                while ( n < terms->length() ) {
                    char c = (*terms)[n++];
                    if ( c == ' ' || c == '+' )
                        c = '&';
                    arg.append( c );
                }
            }

            d->searchQuery = new Query( s, this );
            d->searchQuery->bind( 1, d->link->mailbox()->id() );
            d->searchQuery->bind( 2, arg );
        }
        d->searchQuery->execute();
    }
    if ( !d->searchQuery->done() || !d->mailboxView->ready() )
        return;

    String s( "<div class=page>" );
    s.append( leftContent() );
    s.append( "<div class=formeriframe>" );
    s.append( fn( d->searchQuery->rows() ) + " results found.<br>" );

    Row * r = d->searchQuery->nextRow();
    while ( r ) {
        uint uid = r->getInt( "uid" );

        MailboxView::Thread * t = d->mailboxView->thread( uid );
        Link result( d->link, d->link->mailbox(), t->uid( 0 ) );
        Message * m = 0;
        //d->mailboxView->mailbox()->message( uid );
        HeaderField * hf = m->header()->field( HeaderField::Subject );
        String subject;
        if ( hf )
            subject = hf->data().simplified();
        if ( subject.isEmpty() )
            subject = "(No Subject)";
        s.append( "<div class=thread>\n"
                  "<div class=headerfield>Subject: " );
        s.append( htmlQuoted( subject ) );
        s.append( "</div>\n" ); // subject

        s.append( "<div class=threadcontributors>\n" );
        s.append( "<div class=headerfield>From:\n" );

        s.append( "<a href=\"" );
        s.append( result.string() );
        s.append( "#" );
        s.append( fn( uid ) );
        s.append( "\">" );
        AddressField * af
            = m->header()->addressField( HeaderField::From );
        if ( af ) {
            List< Address >::Iterator it( af->addresses() );
            while ( it ) {
                s.append( address( it ) );
                ++it;
                if ( it )
                    s.append( ", " );
            }
        }
        s.append( "</a>" );
        s.append( "\n" );
        s.append( "</div>\n" // headerfield
                  "</div>\n" // threadcontributors
                  "</div>\n" ); // thread
        r = d->searchQuery->nextRow();
    }
    s.append( "</div></div>" );

    d->text = s;
    d->ready = true;
}


/*! Just like webmailSearchPage(); probably they should share search
    and do individual presentation.
*/

void Page::archiveSearchPage()
{
    d->ready = true;
    d->text = "Kilroy might eventually be somewhere. Search for him.";
}


/*! Returns a string containing the HTML that represents the left column
    of the final web page.
*/

String Page::leftContent()
{
    Mailbox * m = d->server->session()->user()->home();

    String s = "<div id=leftcontent>"
               "<div class=actions>"
               "<div class=search>"
               "<form method=post action=\"/" + fn( d->link->mailbox()->id() ) +
               "/search\">"
               "<input type=text name=query>"
               "<input type=submit value=search>"
               "</form>"
               "</div>\n" // search
               "<div class=actionbuttons>\n"
               "<a href=\"/logout\">Logout</a>\n"
               "<a href=\"/compose\">Compose</a>\n"
               "<a href=\"http://www.oryx.com/webmail/help/\">Help</a>\n"
               "<a href=\"/preferences\">Preferences</a>\n"
               "<a href=\"/\">Refresh Mailbox</a>\n" // XXX
               "</div>\n" // actionbuttons
               "<div class=folders>"
               "<p>Folder list\n" +
               mailboxDescriptor( m, m->name().length() ) +
               "</div>\n" // folders
               "</div>\n" // actions
               "</div>\n" // leftcontent
               "<div class=bottom>"
               "</div>\n" // bottom
               ;
    return s;
}


/*! Returns a HTML-formatted string containing the first two lines or
    so of \a m.

    This function heuristically picks the "first" bodypart and even
    more heuristically looks for the "first" text in that bodypart.

    If no bodyparts can be used, this function returns an empty string.
*/

String Page::twoLines( Message * m )
{
    List<Bodypart>::Iterator bp( m->allBodyparts() );
    String type;
    while ( bp && type != "text/plain" && type != "text/html" ) {
        type = "text/plain";
        ContentType * ct = bp->header()->contentType();
        if ( ct )
            type = ct->type() + "/" + ct->subtype();
    }

    String r;
    if ( !bp ) {
        r = "(Cannot display summary of nontext message)";
    }
    else if ( type == "text/plain" ) {
#if 0
        Utf8Codec u; // XXX UString needs find() and more.
        String b = u.fromUnicode( bp->text() );
        int i = 0;
        while ( i >= 0 && b[i] == '>' && b[i] > ' ' ) {
            i = b.find( '\n', i + 1 );
            if ( i >= 0 )
                i++;
        }
        int e = b.find( '\n', i + 1 );
        if ( e < i )
            e = b.length();
        r = textPlain( b.mid( i, e-i ) );
#else
        r = "(Cannot display text/plain summary)";
#endif
    }
    else if ( type == "text/html" ) {
        r = "(Cannot display summary of HTML message)";
    }

    return r;
}
