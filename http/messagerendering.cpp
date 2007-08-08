// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "messagerendering.h"

#include "codec.h"
#include "list.h"
#include "utf.h"


class MessageRenderingData
    : public Garbage
{
public:
    MessageRenderingData()
        : Garbage(), wp( 0 ), codec( 0 ), flowed( false ), root( 0 ) {}

    WebPage * wp;
    UString text;
    String html;
    Codec * codec;
    bool flowed;

    class Node
        : public Garbage
    {
    public:
        Node(): Garbage(), parent( 0 ), variables( 0 ) {}

        UString text;
        String tag;
        String htmlclass;
        String href;

        List<Node> children;
        class Node * parent;
        Dict<String> * variables;

        String rendered() const;
        void clean();
        bool known() const;
        bool container() const;
        bool lineLevel() const;
    };

    Node * root;
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

void MessageRendering::setTextHtml( const String & s, Codec * c )
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

String MessageRendering::asHtml()
{
    render();
    return d->root->rendered();
}


/*! This helper turns text/plain into HTML. */

void MessageRendering::renderText()
{
    d->root = new MessageRenderingData::Node;
    d->root->tag = "div";
    d->root->htmlclass = "textplain";
    MessageRenderingData::Node * p = 0;
    MessageRenderingData::Node * n = 0;
    uint i = 0;
    uint c = 0;
    bool quoted = false;
    bool newPara = true;
    while ( i < d->text.length() ) {
        c = d->text[i];
        if ( newPara ) {
            p = new MessageRenderingData::Node;
            p->tag = "p";
            d->root->children.append( p );
            p->parent = d->root;
            n = new MessageRenderingData::Node;
            p->children.append( n );
            n->parent = p;
            quoted = false;
            if ( c == '>' ) {
                p->htmlclass = "quoted";
                quoted = true;
            }
            newPara = false;
        }

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
            if ( !newPara ) {
                n = new MessageRenderingData::Node;
                p->children.append( n );
                n->parent = p;
                n->tag = "br";
                n = new MessageRenderingData::Node;
                p->children.append( n );
                n->parent = p;
            }
        }
        else if ( c == 8 ) {
            // backspace
            if ( n && !n->text.isEmpty() )
                n->text.truncate( n->text.length() - 1 );
            i++;
        }
        else {
            // other text
            n->text.append( c );
            i++;
        }
    }
}


/*! This helper renders the input as plain HTML, without anything that
    might expose the browser to problems (javascript, webbugs, overly
    inventive syntax, look&feel that mimics our user interface, that
    sort of thing).

    It is public for convenience and ease of testing. It should not be
    called by other classes.
*/

void MessageRendering::renderHtml()
{
    d->root = new MessageRenderingData::Node;
    d->root->tag = "div";
    d->root->htmlclass = "texthtml";

    MessageRenderingData::Node * t = 0;
    MessageRenderingData::Node * p = d->root;
    bool seenBody = true;

    uint i = 0;
    while ( i < d->html.length() ) {
        uint j = i;
        while ( j < d->html.length() && d->html[j] != '<' )
            j++;
        if ( j > i ) {
            if ( !t ) {
                t = new MessageRenderingData::Node;
                p->children.append( t );
                t->parent = p;
            }
            t->text.append( d->codec->toUnicode( d->html.mid( i, j-i ) ) );
            i = j;
        }
        if ( d->html[i] == '<' ) {
            i++;
            j = i;
            while ( j < d->html.length() &&
                    d->html[j] != ' ' && d->html[j] != '>' )
                j++;
            MessageRenderingData::Node * n =
                new MessageRenderingData::Node;
            n->tag = d->html.mid( i, j-i ).lower();
            n->variables = parseVariables( i );

            String unwind;
            if ( n->tag[0] == '/' )
                unwind = n->tag.mid( 1 );
            else if ( n->tag == "p" )
                unwind = n->tag;
            else if ( n->tag == "li" )
                unwind = n->tag;
            else if ( n->tag == "td" )
                unwind = n->tag;
            if ( !unwind.isEmpty() ) {
                n = t;
                if ( !n )
                    n = p;
                while ( n && n->tag != unwind )
                    n = n->parent;
                if ( n && n->parent ) {
                    p = n->parent;
                    t = 0;
                }
            }

            if ( n->tag[0] != '/' ) {
                p->children.append( n );
                n->parent = p;
                if ( n->container() )
                    p = n;
                t = 0;
            }
            if ( !seenBody && n->tag == "body" ) {
                d->root = n;
                d->root->tag = "div";
                d->root->htmlclass = "texthtml";
                d->root->parent = 0;
                seenBody = true;
            }
        }
    }
}


/*! Parses a series of name or name=value arguments in an HTML tag,
    moving \a i to the first byte after the last variable. Actually it
    skips whitespace after the last variable, too, it \a i should point
    to '>' for all wellformed html.

    Returns a pointer to a dictionary of name/value pairs. Silently
    throws away anything with parse errors, empty or nonexistent
    values, or other shady appearance.
*/

Dict<String> * MessageRendering::parseVariables( uint & i )
{
    Dict<String> * v = new Dict<String>;
    String name;
    do {
        while ( d->html[i] == ' ' ||
                d->html[i] == '\t' ||
                d->html[i] == '\r' ||
                d->html[i] == '\n' )
            i++;
        uint j = i;
        while ( i < d->html.length() &&
                d->html[i] != '>' && d->html[i] != '=' )
            j++;
        name = d->html.mid( j, i-j ).simplified().lower();
        if ( !name.isEmpty() && d->html[i] == '=' ) {
            i++;
            String value;
            while ( d->html[i] == ' ' || d->html[i] == '\t' ||
                    d->html[i] == 13 || d->html[i] == 10 )
                i++;
            if ( d->html[i] == '"' ) {
                j = i+1;
                uint lt = 0;
                while ( j < d->html.length() &&
                        d->html[j] != '"' &&
                        d->html[j] != 10 &&
                        d->html[j] != 13 ) {
                    if ( d->html[j] == '>' && !lt )
                        lt = j;
                    j++;
                }
                if ( d->html[j] != '"' && lt )
                    j = lt;
                value = d->html.mid( i, j-i );
                i = j;
                if ( d->html[i] == '"' )
                    i++;
            }
            else {
                j = i+1;
                while ( j < d->html.length() &&
                        d->html[j] != '>' &&
                        d->html[j] != 10 && d->html[j] != 13 &&
                        d->html[j] != ' ' && d->html[j] != '\t' )
                    j++;
                value = d->html.mid( i, j-i );
                i = j;
            }
            // at this point we have a name and a value, but the value
            // isn't known to be sane. so we check that:
            // a) we only have one value for this name
            // b) the name doesn't look overly exciting
            // c) the value doesn't contain illegal percent-escapes
            //    which might attack the browser
            // d) the value doesn't contain badly-formed unicode which
            //    might trick the browser into seeing null bytes where
            //    none are permitted or similar evil
            if ( name.boring() && !value.isEmpty() && !v->contains( name ) ) {
                String v8;
                uint p = 0;
                bool ok = true;
                while ( ok && p < value.length() ) {
                    char c = value[p];
                    if ( c == '%' ) {
                        uint n = c;
                        if ( value.length() > p + 2 )
                            n = value.mid( p+1, 2 ).number( &ok, 16 );
                        else
                            ok = false;
                        if ( ok ) {
                            p += 2;
                            c = (char)n;
                        }
                    }
                    v8.append( c );
                    p++;
                }
                if ( ok ) {
                    // some links may be correct and benevolent even
                    // though the percent escapes aren't valid
                    // unicode. but how are we to know what's
                    // benevolent and what's malevolent in these
                    // cases? better to be strict.
                    Utf8Codec u;
                    (void)u.toUnicode( v8 );
                    if ( u.wellformed() )
                        v->insert( name, new String( value ) );
                }
            }
        }
    } while ( !name.isEmpty() );
    return v;
}


void MessageRenderingData::Node::clean()
{
    // tighten up quoted matter
    if ( tag == "blockquote" ) {
        tag = "p";
        htmlclass = "quoted";
    }
    else if ( variables && 
              variables->contains( "cite" ) ) {
        tag = "p";
        htmlclass = "quoted";
    }
    else if ( variables && 
              variables->contains( "type" ) &&
              variables->find( "type" )->lower() == "cite" ) {
        tag = "p";
        htmlclass = "quoted";
    }

    // some kinds of tags enclose matter we simply don't want
    if ( tag == "script" || tag == "style" ||
         tag == "meta" || tag == "head" ) {
        children.clear();
        text.truncate();
    }

    // identify <div><div><div> ... </div></div></div> and remove the
    // inner divs.
    while ( children.count() == 1 &&
            ( tag == "div" || tag == "p" ) &&
            children.first()->tag == tag ) {
        Node * c = children.first();
        children.clear();
        List<Node>::Iterator i( c->children );
        while ( i ) {
            children.append( i );
            i->parent = this;
        }
    }

    // todo: identify signatures

    // todo: mark the last line before a signature block if it seems
    // to be "x y schrieb"

    // todo: mark "---original message---" and subsequent as quoted
    // matter.

    // todo: identify disclaimers

    // todo: identify ascii art and mark it as <pre> or something.

    // todo: identify leading greeting and mark it

    // process children
    List<Node>::Iterator i( children );
    while ( i ) {
        Node * n = i;
        ++i;
        n->clean();
    }
}


bool MessageRenderingData::Node::known() const
{
    if ( tag == "p" ||
         tag == "li" ||
         tag == "a" ||
         tag == "i" ||
         tag == "b" ||
         tag == "u" ||
         tag == "em" ||
         tag == "strong" ||
         tag == "div" ||
         tag == "span" ||
         tag == "ul" ||
         tag == "ol" ||
         tag == "dl" ||
         tag == "dt" ||
         tag == "dd" ||
         tag == "pre" ||
         tag == "table" ||
         tag == "tr" ||
         tag == "td" ||
         tag == "th" ||
         tag == "blockquote" ||
         tag == "br" ||
         tag == "hr" ||
         tag == "meta" ||
         tag == "script" ||
         tag == "style" ||
         tag == "body" )
        return true;
    return false;
}


bool MessageRenderingData::Node::container() const
{
    if ( tag == "br" ||
         tag == "hr" )
        return false;
    if ( known() )
        return true;
    return false;
}


bool MessageRenderingData::Node::lineLevel() const
{
    if ( tag == "a" ||
         tag == "span" ||
         tag == "i" || tag == "o" || tag == "u" ||
         tag == "em" || tag == "strong" )
        return true;
    return false;
}


static void ensureTrailingLf( String & r )
{
    int i = r.length() - 1;
    while ( i >= 0 && 
            ( r[i] == ' ' || r[i] == '\t' ||
              r[i] == '\r' || r[i] == '\n' ) )
        i--;
    r.truncate( i + 1 );
    if ( !r.isEmpty() )
        r.append( "\n" );
}



String MessageRenderingData::Node::rendered() const
{
    String r;
    bool pre = false;
    const Node * p = this;
    while ( !pre && p && p->tag != "pre" )
        p = p->parent;
    if ( container() ) {
        String n = "div";
        if ( tag == "a" )
            n = "span"; // we don't let links through...
        else if ( known() )
            n = tag;
        r.append( "<" );
        r.append( n );
        if ( !htmlclass.isEmpty() ) {
            r.append( " class=" );
            if ( htmlclass.boring() )
                r.append( htmlclass );
            else
                r.append( htmlclass.quoted() );
        }
        r.append( ">" );
        if ( !pre && !lineLevel() )
            r.append( "\n" );
        List<Node>::Iterator i( children );
        bool first = true;
        while ( i ) {
            String e = i->rendered();
            uint b = 0;
            if ( !pre ) {
                while ( e[b] == ' ' || e[b] == '\t' ||
                        e[b] == '\r' || e[b] == '\n' )
                    b++;
                ensureTrailingLf( r );
                if ( first && lineLevel() )
                    r.truncate( r.length()-1 );
            }
            r.append( e.mid( b ) );
            first = false;
            ++i;
        }
        if ( n != "p" && n != "li" ) {
            if ( !pre && !lineLevel() )
                ensureTrailingLf( r );
            r.append( "</" );
            r.append( n );
            r.append( ">" );
            if ( !pre )
                r.append( "\n" );
        }
        if ( children.isEmpty() )
            r.truncate();
    }
    else if ( !tag.isEmpty() ) {
        if ( known() ) {
            r.append( "<" );
            r.append( tag );
            r.append( ">" );
            if ( !pre )
                r.append( "\n" );
        }
    }
    else if ( !text.isEmpty() ) {
        bool ll = lineLevel();
        r.reserve( text.length() );
        uint i = 0;
        uint spaces = 0;
        while ( i < text.length() ) {
            uint c = text[i];
            i++;
            if ( !pre &&
                 ( c == 9 || c == 10 || c == 13 || c == 32 ) ) {
                spaces++;
            }
            else {
                if ( spaces && ( ll || !r.isEmpty() ) )
                    r.append( ' ' );
                spaces = 0;
                if ( c > 126 ||
                     ( c < 32 && c != 9 && c != 10 && c != 13 ) ) {
                    r.append( "&#" );
                    r.append( fn( c ) );
                    r.append( ';' );
                }
                else if ( c == '<' ) {
                    r.append( "&lt;" );
                }
                else if ( c == '>' ) {
                    r.append( "&gt;" );
                }
                else if ( c == '&' ) {
                    r.append( "&amp;" );
                }
                else {
                    r.append( (char)c );
                }
            }
        }
        if ( ll && spaces )
            r.append( ' ' );
        if ( !pre && !ll )
            r = r.wrapped( 72, "", "", false );
    }
    return r;
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
    UString r;
    MessageRenderingData::Node * n = d->root;
    while ( n && r.length() < 300 ) {
        if ( n != d->root && !n->htmlclass.isEmpty() ) {
            // it's quoted or something
        }
        else {
            if ( !n->text.isEmpty() ) {
                r.append( '\n' );
                r.append( '\n' );
                r.append( n->text );
            }
            else if ( n->tag == "hr" || n->tag == "br" ) {
                r.append( '\n' );
            }
            if ( !n->children.isEmpty() ) {
                n = n->children.first();
            }
            else if ( n->parent ) {
                MessageRenderingData::Node * c = 0;
                MessageRenderingData::Node * p = n->parent;
                while ( p && !c ) {
                    List<MessageRenderingData::Node>::Iterator i(p->children);
                    while ( i && i != n )
                        ++i;
                    if ( i )
                        c = ++i;
                    else
                        p = p->parent;
                }
            }
            else {
                n = 0;
            }
        }

    }
    return r;
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
