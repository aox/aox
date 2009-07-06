// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "messagerendering.h"

#include "ustringlist.h"
#include "htmlparser.h"
#include "entities.h"
#include "codec.h"
#include "utf.h"


class MessageRenderingData
    : public Garbage
{
public:
    MessageRenderingData()
        : Garbage(), wp( 0 ), codec( 0 ), flowed( false ), root( 0 ) {}

    WebPage * wp;
    UString text;
    EString html;
    Codec * codec;
    bool flowed;

    HtmlNode * root;
};



/*! \class MessageRendering messagerendering.h

    The MessageRendering provides HTML rendering of message bodyparts
    and access to the rendered data. It's used for displaying incoming
    email in a safe way (ie. without letting the email attack the
    webmail system, browser or user), for extracting text from email,
    and for displaying extracts.
*/



/*!  Constructs an empty MessageRendering object. setTextPlain() or
     setTextHtml() is needed.
*/

MessageRendering::MessageRendering()
    : Garbage(), d( new MessageRenderingData )
{
    // a bugfree function?
}


/*! Records that \a s is what should be rendered. */

void MessageRendering::setTextPlain( const UString & s )
{
    d->root = 0;
    d->html.truncate();
    d->codec = 0;
    d->text = s;
    d->flowed = false;
}


/*! Records that \a s is what should be rendered. */

void MessageRendering::setTextFlowed( const UString & s )
{
    d->root = 0;
    d->html.truncate();
    d->codec = 0;
    d->text = s;
    d->flowed = true;
}


/*! Records that \a s is what should be rendered, and that \a c must be
  used to convert it to unicode.
*/

void MessageRendering::setTextHtml( const EString & s, Codec * c )
{
    d->root = 0;
    d->text.truncate();
    d->html = s;
    d->codec = c;
    d->flowed = false;
}


/*! Instructs the MessageRendering to generate 'id=x' based on the
    WebPage::uniqueNumber() member of \a wp. The MessageRendering
    object will try to use as few IDs as possible, but there's no
    guarantee that it.
*/

void MessageRendering::setWebPage( class WebPage * wp )
{
    d->wp = wp;
    d->root = 0;
}


/*! Returns a safe HTML rendering of the input supplied earlier. May
    do the rendering work, but tries to return the same string as an
    earlier call.
*/

EString MessageRendering::asHtml()
{
    render();
    return d->root->rendered();
}


/*! This helper turns text/plain into HTML. */

void MessageRendering::renderText()
{
    d->root = new HtmlNode( 0, "div" );
    d->root->setHtmlClass( "textplain" );

    HtmlNode * p = 0;
    HtmlNode * n = 0;
    uint i = 0;
    uint c = 0;
    bool quoted = false;
    bool newPara = true;
    while ( i < d->text.length() ) {
        c = d->text[i];
        if ( c == 13 || c == 10 ) {
            // CR, LF or a combination
            uint cr = 0;
            uint lf = 0;
            bool done = false;
            do {
                c = d->text[i];
                if ( c == 13 ) {
                    cr++;
                    i++;
                }
                else if ( c == 10 ) {
                    lf++;
                    i++;
                }
                else {
                    done = true;
                }
            } while ( !done );
            if ( cr > 1 || lf > 1 )
                newPara = true;
            if ( quoted && c != '>' )
                newPara = true;
            else if ( !quoted && c == '>' )
                newPara = true;
            if ( p && !newPara ) {
                n = new HtmlNode( p, "br" );
                n = new HtmlNode( p );
            }
        }
        else if ( c == 8 ) {
            // backspace
            if ( n && !n->text().isEmpty() )
                n->text().truncate( n->text().length() - 1 );
            i++;
        }
        else {
            // other text
            if ( newPara ) {
                p = new HtmlNode( d->root, "p" );
                n = new HtmlNode( p );
                quoted = false;
                if ( c == '>' ) {
                    p->setHtmlClass( "quoted" );
                    quoted = true;
                }
                newPara = false;
            }
            n->text().append( c );
            i++;
        }
    }
}


/*! Uses an HtmlParser to construct a parse tree from the HTML input. */

void MessageRendering::renderHtml()
{
    HtmlParser * hp = new HtmlParser( d->html, d->codec );
    d->root = hp->rootNode();
}


/*! This private helper does nothing, calls renderHtml() or
    renderText(), whichever is appropriate.
*/

void MessageRendering::render()
{
    if ( d->root )
        return;

    if ( !d->html.isEmpty() )
        renderHtml();
    else
        renderText();

    d->root->clean();
}


static void trimTrailingSpaces( UString & r )
{
    uint i = r.length() - 1;
    while ( i > 0 && ( r[i] == ' ' || r[i] == '\t' || r[i] == '\r' ||
                       r[i] == '\n' || r[i] == '.' || r[i] == ',' ||
                       r[i] == ':' ) )
        i--;
    r.truncate( i+1 );
}


/*! Finds and returns an excerpt from the message. Avoids quoted bits,
    scripts, style sheets etc., removes formatting wholesale and
    blah. Rather heuristic.

    Two or linefeeds in a row probably ought to be turned into <p> and
    one into <br>.
*/

UString MessageRendering::excerpt()
{
    render();
    UStringList excerpts;
    excerpts.append( new UString );
    d->root->findExcerpt( &excerpts );
    UString r;
    if ( !excerpts.isEmpty() )
        r = *excerpts.first();
    trimTrailingSpaces( r );
    if ( r.length() < 100 && !r.contains( '\n' ) &&
         excerpts.count() > 1 ) {
        UStringList::Iterator i( excerpts );
        ++i;
        if ( i && i->length() > 100 )
            r = *i;
    }
    uint i = 300;
    uint j = 0;
    while ( j < 20 && r[i+j] != ' ' && r[i-j] != ' ' )
        j++;
    if ( r[i-j] == ' ' )
        r.truncate( i - j + 1 );
    else
        r.truncate( i + j + 1 );
    trimTrailingSpaces( r );
    r.append( 8230 ); // ellipsis
    return r;
}
