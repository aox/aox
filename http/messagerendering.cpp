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
        : Garbage(), wp( 0 ), codec( 0 ), root( 0 ) {}

    WebPage * wp;
    UString text;
    String html;
    Codec * codec;

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
    if ( d->root )
        return d->root->rendered();

    if ( !d->html.isEmpty() )
        renderHtml();
    else
        renderText();
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
    bool quoted = false;
    bool newPara = true;
    while ( i < d->text.length() ) {
        if ( newPara ) {
            p = new MessageRenderingData::Node;
            p->tag = "p";
            d->root->children.append( p );
            p->parent = d->root;
            n = new MessageRenderingData::Node;
            p->children.append( n );
            n->parent = p;
            quoted = false;
            if ( d->text[i] == '>' ) {
                p->htmlclass = "quoted";
                quoted = true;
            }
            newPara = false;
        }

        if ( d->text[i] == 13 || d->text[i] == 10 ) {
            // CR, LF or a combination
            uint cr = 0;
            uint lf = 0;
            bool done = false;
            do {
                if ( d->text[i] == 13 ) {
                    cr++;
                    i++;
                }
                else if ( d->text[i] == 10 ) {
                    lf++;
                    i++;
                }
                else {
                    done = true;
                }
            } while ( !done );
            if ( cr > 1 || lf > 1 )
                newPara = true;
            if ( quoted && d->text[i] != '>' )
                newPara = true;
            else if ( !quoted && d->text[i] == '>' )
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
        else if ( d->text[i] == 8 ) {
            // backspace
            if ( n && !n->text.isEmpty() )
                n->text.truncate( n->text.length() - 1 );
            i++;
        }
        else {
            // other text
            d->text.append( d->text[i] );
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
         tag == "hr" ||
         tag == "meta" )
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


static void truncateTrailingWhitespace( String & r )
{
    int i = r.length() - 1;
    bool done = false;
    while ( i >= 0 && !done ) {
        switch ( r[i] ) {
        case ' ':
        case '\t':
        case '\r':
        case 'n':
            i--;
            break;
        default:
            done = true;
            break;
        }
    }
    if ( i < 0 )
        i = 0;
    r.truncate( i );
}



String MessageRenderingData::Node::rendered() const
{
    if ( tag == "style" || tag == "script" )
        return "";

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
        if ( pre )
            r.append( "\n" );
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
        while ( i ) {
            String e = i->rendered();
            ++i;
            if ( !pre &&
                 ( e[0] == ' ' || e[0] == '\t' ||
                   e[0] == '\r' || e[0] == '\n' ) )
                truncateTrailingWhitespace( r );
            r.append( e );
        }
        if ( !pre && !lineLevel() )
            r.append( "\n" );
        r.append( "</" );
        r.append( n );
        r.append( ">" );
        if ( !pre )
            r.append( "\n" );
    }
    else if ( !tag.isEmpty() ) {
        if ( known() && tag != "meta" ) {
            if ( !pre )
                r.append( "\n" );
            r.append( "<" );
            r.append( tag );
            r.append( "<" );
            if ( !pre )
                r.append( "\n" );
        }
    }
    else if ( !text.isEmpty() ) {
        bool ll = lineLevel();
        r.reserve( text.length() );
        uint i = 0;
        uint spaces = 0;
        UString t;
        t.reserve( text.length() );
        while ( i < text.length() ) {
            if ( text[i] != 8 )
                t.append( text[i] );
            else if ( !t.isEmpty() && t[t.length()-1] >= 32 )
                t.truncate( t.length() - 1 );
            i++;
        }
        i = 0;
        while ( i < t.length() ) {
            uint c = t[i];
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
                    r.append( c );
                }
            }
            i++;
        }
        if ( ll && spaces )
            r.append( ' ' );
        if ( !pre && !ll )
            r = r.wrapped( 72, "", "", false );
    }
    return r;
}
