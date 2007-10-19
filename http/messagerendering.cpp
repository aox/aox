// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "messagerendering.h"

#include "ustringlist.h"
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

        void findExcerpt( UStringList * ) const;
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
    bool seenBody = false;

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
            t->text.append( toUnicode( d->codec, d->html.mid( i, j-i ) ) );
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
            i++;

            String unwind;
            if ( n->tag[0] == '/' )
                unwind = n->tag.mid( 1 );
            else if ( n->tag == "p" )
                unwind = n->tag;
            else if ( n->tag == "li" )
                unwind = n->tag;
            
            if ( !unwind.isEmpty() ) {
                MessageRenderingData::Node * n = t;
                if ( !n )
                    n = p;
                while ( n && n->tag != unwind )
                    n = n->parent;
                if ( n && n->parent ) {
                    p = n->parent;
                    t = 0;
                }
            }
            else if ( n->container() && !n->lineLevel() ) {
                // if we see a non-line-level container tag, we close
                // the currently open line-level tags.
                MessageRenderingData::Node * n = p;
                while ( n && n->lineLevel() )
                    n = n->parent;
                if ( n && !n->lineLevel() ) {
                    p = n;
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
            i++;
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

    // get rid of quoting prefixes
    if ( container() ) {
        bool first = true;
        bool ok = false;
        UString prefix;
        List<Node>::Iterator c( children );
        while ( c ) {
            if ( c->htmlclass == "quoted" ) {
                List<Node>::Iterator qc( c->children );
                while ( qc ) {
                    if ( qc->text.isEmpty() ) {
                    }
                    else if ( first ) {
                        first = false;
                        prefix = qc->text;
                    }
                    else {
                        uint i = 0;
                        while ( i < prefix.length() && i < qc->text.length() &&
                                prefix[i] == qc->text[i] )
                            i++;
                        prefix.truncate( i );
                    }
                    if ( prefix.length() < qc->text.length() )
                        ok = true;
                    ++qc;
                }
            }
            ++c;
        }
        if ( ok && !prefix.isEmpty() ) {
            c = children.first();
            while ( c ) {
                if ( c->htmlclass == "quoted" ) {
                    List<Node>::Iterator qc( c->children );
                    while ( qc ) {
                        qc->text = qc->text.mid( prefix.length() );
                        ++qc;
                    }
                }
                ++c;
            }
        }
    }

    // some kinds of tags enclose matter we simply don't want
    if ( tag == "script" || tag == "style" ||
         tag == "meta" || tag == "head" ) {
        children.clear();
        text.truncate();
        tag = "";
    }

    // identify and remove sequences of ""/<br> in paragraphs
    if ( container() && !lineLevel() && tag != "pre" ) {
        bool br = true;
        List<Node>::Iterator i( children );
        // remove all <br>/whitespace after <br> or at the start
        while ( i ) {
            if ( br &&
                 ( i->tag == "br" ||
                   ( i->tag.isEmpty() &&
                     i->text.simplified().isEmpty() ) ) ) {
                children.take( i );
            }
            else {
                if ( i->tag == "br" )
                    br = true;
                else
                    br = false;
                ++i;
            }
        }

        // ... ditto before the end
        while ( !children.isEmpty() && 
                ( children.last()->tag == "br" ||
                  ( children.last()->tag.isEmpty() &&
                    children.last()->text.simplified().isEmpty() ) ) )
            children.take( children.last() );
    }

    // identify <div><div><div> ... </div></div></div> and remove the
    // inner divs.
    if ( tag == "div" ) {
        while ( children.count() == 1 &&
                children.first()->tag == tag ) {
            Node * c = children.first();
            children.clear();
            List<Node>::Iterator i( c->children );
            while ( i ) {
                children.append( i );
                i->parent = this;
                ++i;
            }
            if ( htmlclass.isEmpty() )
                htmlclass = c->htmlclass;
        }
    }

    // identify signatures
    if ( parent && htmlclass.isEmpty() && tag == "p" && 
         !children.isEmpty() ) {
        List<Node>::Iterator i( children );
        bool sigmarker = false;
        while ( i && !sigmarker ) {
            UString t = i->text;
            if ( t.startsWith( "-- " ) &&
                 ( t.simplified() == "--" ||
                   t.startsWith( "-- \n" ) ) )
                sigmarker = true;
            else
                ++i;
            // this is a shade dubious, it marks the paragraph
            // including -- as a sig, even if -- doesn't start the
            // paragraph. in practice it works well, at least it seems
            // to:
            //
            // cheers
            // gert
            // --
            // gert@example.nl
            // more blah here
        }
        if ( sigmarker ) {
            // if the remaining children of my parent are unmarked,
            // make a surrounding div and mark it as a signature.
            List<Node>::Iterator i( parent->children );
            while ( i && i != this )
                ++i;
            if ( i == this ) {
                uint c = 0;
                List<Node>::Iterator n = i;
                while ( n && n->htmlclass.isEmpty() ) {
                    c++;
                    ++n;
                }
                if ( c < 4 &&
                     ( !n || n->htmlclass == "quoted" ) ) {
                    Node * div = new Node;
                    parent->children.insert( i, div );
                    div->parent = parent;
                    div->tag = "div";
                    div->htmlclass = "signature";
                    while ( i && i != n ) {
                        div->children.append( i );
                        i->parent = div;
                        parent->children.take( i ); // moves i
                    }
                }
            }
        }
    }

    // todo: mark the last line before a quoted block if it seems
    // to be "x y schrieb"

    // mark "---original message---" and subsequent as quoted matter.
    if ( parent && htmlclass.isEmpty() && tag == "p" && 
         !children.isEmpty() ) {
        UString t = children.first()->text;
        if ( t == "-----Original Message-----" ) {
            List<Node>::Iterator i( parent->children );
            while ( i && i != this )
                ++i;
            if ( i == this ) {
                while ( i && i->container() && i->htmlclass.isEmpty() ) {
                    i->htmlclass = "quoted";
                    ++i;
                }
            }
        }
    }

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

    // finally, if that left this node effectively empty, remove it entirely
    if ( parent && 
         ( ( tag.isEmpty() && text.simplified().isEmpty() ) ||
           ( container() && children.isEmpty() ) ) ) {
        List<Node>::Iterator i( parent->children );
        while ( i && i != this )
            ++i;
        if ( i )
            parent->children.take( i );
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
         tag == "i" || tag == "o" || tag == "u" || tag == "b" ||
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


static String entityName( uint c )
{
    String r;
    switch ( c ) {
#include "entitynames.inc"
    default:
        r.append( "&#" );
        r.append( fn( c ) );
        r.append( ";" );
        break;
    }
    return r;
}



String MessageRenderingData::Node::rendered() const
{
    String r;
    bool pre = false;
    const Node * p = this;
    while ( p && p->tag != "pre" )
        p = p->parent;
    if ( p && p->tag == "pre" )
        pre = true;
    if ( container() ) {
        String n;
        if ( tag != "a" && known() )
            n = tag;
        if ( !n.isEmpty() ) {
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
        }
        bool contents = false;
        List<Node>::Iterator i( children );
        while ( i ) {
            String e = i->rendered();
            if ( e.isEmpty() ) {
                // forget it
            }
            else if ( !pre && e.simplified().isEmpty() ) {
                // forget it harder
            }
            else {
                bool lfbefore;
                if ( pre )
                    lfbefore = false;
                else if ( r.endsWith( " " ) || r.endsWith( "\n" ) )
                    lfbefore = true;
                else if ( e.startsWith( " " ) || e.startsWith( "\n" ) )
                    lfbefore = true;
                else if ( i->lineLevel() )
                    lfbefore = false;
                else if ( i->container() )
                    lfbefore = true;
                else if ( lineLevel() )
                    lfbefore = false;
                else if ( !i->tag.isEmpty() )
                    lfbefore = true;
                else
                    lfbefore = false;
                if ( lfbefore )
                    ensureTrailingLf( r );
                uint b = 0;
                if ( !pre )
                    while ( e[b] == ' ' || e[b] == '\t' ||
                            e[b] == '\r' || e[b] == '\n' )
                        b++;
                if ( b < e.length() ) {
                    r.append( e.mid( b ) );
                    contents = true;
                }
            }
            ++i;
        }
        if ( !n.isEmpty() && n != "p" && n != "li" ) {
            if ( !pre && !lineLevel() )
                ensureTrailingLf( r );
            r.append( "</" );
            r.append( n );
            r.append( ">" );
            if ( !pre && !lineLevel() )
                r.append( "\n" );
        }
        if ( !contents )
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
        r.reserve( text.length() );
        UString t;
        if ( pre ) {
            t = text;
        }
        else {
            t.append( 't' );
            t.append( text );
            t.append( 't' );
            t = t.simplified();
            t = t.mid( 1, t.length() - 2 );
        }
        uint i = 0;
        while ( i < t.length() ) {
            uint c = t[i];
            i++;
            if ( c > 126 ||
                 ( c < 32 && c != 9 && c != 10 && c != 13 ) ||
                 c == '<' ||
                 c == '>' ||
                 c == '&' )
                r.append( entityName( c ) );
            else
                r.append( (char)c );
        }
        if ( !pre ) {
            String w = r.wrapped( 72, "", "", false );
            // wrapped uses CRLF, which we turn to LF for easier testing
            r.truncate();
            i = 0;
            while ( i < w.length() ) {
                if ( w[i] != '\r' )
                    r.append( w[i] );
                i++;
            }
        }
    }
    return r;
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


void MessageRenderingData::Node::findExcerpt( UStringList * excerpts ) const
{
    if ( parent && !htmlclass.isEmpty() ) {
        if ( excerpts->isEmpty() || !excerpts->last()->isEmpty() )
            excerpts->append( new UString );
        return;
    }
    UString r = text.simplified();
    if ( r.isEmpty() && ( tag == "hr" || tag == "br" ) )
        r.append( "\n" );
    excerpts->last()->append( r );
    List<Node>::Iterator i( children );
    while ( i ) {
        i->findExcerpt( excerpts );
        ++i;
    }
    if ( container() && !lineLevel() && !excerpts->last()->isEmpty() )
        excerpts->last()->append( "\n\n" );
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


static uint entity( const String & s )
{
    if ( s.startsWith( "&#" ) ) {
        bool ok = true;
        uint n;
        if ( s[2] == 'x' )
            n = s.mid( 3 ).number( &ok, 16 );
        else
            n = s.mid( 2 ).number( &ok );
        if ( n >= 0x110000 ||                 // > end of unicode
             ( n >= 0xD800 && n <= 0xDFFF ) ) // lone surrogate
            ok = false;
        if ( ok )
            return n;
    }
    else {
        String e = s.mid( 1 );
        uint bottom = 0;
        uint top = ents;
        // an array and a binary search is _almost_ the same as a
        // binary tree, and one _could_ argue it's more powerful, not?
        while ( bottom < top ) {
            uint n = (bottom+top)/2;
            if ( e == entities[n].name )
                return entities[n].chr;
            else if ( e < entities[n].name )
                top = n;
            else
                bottom = n + 1;
        }
    }
    return 0xFFFD; // "not convertible to unicode"
}


/*! Parses \a s as "html text" (ie. including &amp; and suchlike" and
    returns unicode. \a c is used for all 8-bit blah.
*/

UString MessageRendering::toUnicode( class Codec * c, const String & s )
{
    uint i = 0;
    UString r;
    while ( i < s.length() ) {
        uint b = i;
        while ( i < s.length() && s[i] != '&' )
            ++i;
        if ( i > b )
            r.append( c->toUnicode( s.mid( b, i-b ) ) );
        b = i++;
        while ( ( s[i] >= '0' && s[i] <= '9' ) ||
                ( s[i] >= 'a' && s[i] <= 'z' ) ||
                ( s[i] >= 'A' && s[i] <= 'Z' ) ||
                ( s[i] == '#' ) )
            i++;
        if ( b < s.length() ) {
            r.append( entity( s.mid( b, i-b ) ) );
            if ( s[i] == ';' )
                i++;
        }
    }
    return r;
}
