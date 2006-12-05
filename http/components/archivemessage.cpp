// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivemessage.h"

#include "link.h"
#include "webpage.h"
#include "ustring.h"
#include "stringlist.h"
#include "frontmatter.h"
#include "permissions.h"
#include "addressfield.h"
#include "mimefields.h"
#include "bodypart.h"
#include "fetcher.h"
#include "mailbox.h"
#include "message.h"
#include "header.h"
#include "utf.h"


class ArchiveMessageData
    : public Garbage
{
public:
    ArchiveMessageData()
        : link( 0 ), message( 0 ), uniq( 0 )
    {}

    Link * link;
    Message * message;
    uint uniq;
};


/*! \class ArchiveMessage archivemessage.h
    A page component representing a view of a single message.
*/


/*! Create a new ArchiveMessage for \a link. */

ArchiveMessage::ArchiveMessage( Link * link )
    : PageComponent( "archivemessage" ),
      d( new ArchiveMessageData )
{
    d->link = link;
    addFrontMatter( FrontMatter::jsToggles() );
}


void ArchiveMessage::execute()
{
    if ( !d->message ) {
        Mailbox * m = d->link->mailbox();

        page()->requireRight( m, Permissions::Read );

        d->message = new Message;
        d->message->setUid( d->link->uid() );
        List<Message> messages;
        messages.append( d->message );

        Fetcher * f;

        f = new MessageHeaderFetcher( m, &messages, this );
        f->execute();

        f = new MessageBodyFetcher( m, &messages, this );
        f->execute();

        f = new MessageAddressFetcher( m, &messages, this );
        f->execute();
    }

    if ( !page()->permitted() )
        return;

    if ( !( d->message->hasHeaders() &&
            d->message->hasAddresses() &&
            d->message->hasBodies() ) )
        return;

    setContents( message( d->message, d->message ) );
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


/*! This helper turns \a s into HTML. It is public for convenience and
    ease of testing. It should not be called by other classes.
*/

String ArchiveMessage::textPlain( const String & s )
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

String ArchiveMessage::textHtml( const String & s )
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
                            // and look for > as well as '"'.
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
                // (We should treat <img src="cid:..."> specially.)
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

String ArchiveMessage::bodypart( Message *first, Bodypart *bp )
{
    String s;
    Utf8Codec u;

    Link l;
    l.setType( d->link->type() );
    l.setMailbox( d->link->mailbox() );
    l.setUid( first->uid() );
    l.setPart( first->partNumber( bp ) );

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
        s.append( message( first, bp->message() ) );
        s.append( "</div>\n" );
    }
    else if ( type.startsWith( "image/" ) ) {
        s.append( "<div class=image>" );
        s.append( "<a href=\"" + l.canonical() + "\">" );
        s.append( "<img src=\"" + l.canonical() + "\">" );
        s.append( "</a></div>\n" );
    }
    else if ( type.startsWith( "multipart/" ) ) {
        s.append( "<div class=multipart>\n" );
        List< Bodypart >::Iterator it( bp->children() );
        while ( it ) {
            s.append( bodypart( first, it ) );
            ++it;
        }
        s.append( "</div>\n" );
    }
    else {
        s.append( "<div class=unknown>\n" );

        s.append( "<p>Unknown content type: " );
        s.append( type );
        s.append( "\n" );
        s.append( "<p><a href=\"" + l.canonical() + "\">" );
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
            s.append( quoted( fn ) );
        }

        s.append( "</a>" );
        s.append( " (size " );
        s.append( String::humanNumber( bp->numBytes() ) );
        s.append( ")</div>\n" );
    }

    return s;
}


/*! Returns an HTML representation of the Message \a m, which belongs to
    the Message \a first.
*/

String ArchiveMessage::message( Message *first, Message *m )
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

    /*
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
    */
    s.append( addressField( m, HeaderField::From ) );
    hf = m->header()->field( HeaderField::Subject );
    if ( hf ) {
        s.append( "<div class=headerfield>Subject: " );
        s.append( quoted( hf->data() ) );
        s.append( "</div>\n" );
    }
    s.append( addressField( m, HeaderField::To ) );
    if ( topLevel ) {
        s.append( "<div id=" + optionalHeader + ">\n" );
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
                t.append( quoted( hf->name() ) );
                t.append( ": " );
                t.append( quoted( hf->data().simplified() ) );
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
        s.append( bodypart( first, jt ) );
        ++jt;
    }

    if ( topLevel )
        s.append( "</div>\n" ); // fullBody

    s.append( "</div>\n" ); // message

    return s;
}


/*! Returns an HTML representation of the address field of type \a t in
    the message \a m.
*/

String ArchiveMessage::addressField( Message *m, HeaderField::Type t )
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


String ArchiveMessage::jsToggle( const String &t,
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


/*! Returns a HTML-formatted string containing the first two lines or
    so of \a m.

    This function heuristically picks the "first" bodypart and even
    more heuristically looks for the "first" text in that bodypart.

    If no bodyparts can be used, this function returns an empty string.
*/

String ArchiveMessage::twoLines( Message * m )
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
#if 1
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
