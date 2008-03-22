// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "htmlparser.h"

#include "codec.h"
#include "string.h"
#include "ustringlist.h"
#include "entities.h"
#include "ustring.h"
#include "utf.h"


class HtmlNodeData
    : public Garbage
{
public:
    HtmlNodeData()
        : parent( 0 )
    {}

    HtmlNode * parent;
    List< HtmlNode > children;
    Dict< String > attributes;

    UString text;
    String tag;
    String href;
    String htmlclass;
};


/*! \class HtmlNode htmlparser.h
    Represents a single HTML node (element) in the parse tree.

    Each node has a tag(), some text(), a parent(), and zero or more
    children(). It also knows how to return its rendered() form.
*/

/*! Creates a new HtmlNode as a child of \a parent, with the given
    \a tag. */

HtmlNode::HtmlNode( HtmlNode * parent, const String & tag )
    : d( new HtmlNodeData )
{
    setTag( tag );
    setParent( parent );
}


/*! Returns a pointer to the parent of this node, as specified to the
    constructor. May be 0 for top-level nodes. */

HtmlNode * HtmlNode::parent() const
{
    return d->parent;
}


/*! Sets this node's parent() to \a parent. */

void HtmlNode::setParent( HtmlNode * parent )
{
    d->parent = parent;
    if ( parent )
        parent->addChild( this );
}


/*! Returns a non-zero pointer to the list of children of this node. The
    list may be empty for leaf nodes. */

List< HtmlNode > * HtmlNode::children() const
{
    return &d->children;
}


/*! Returns a non-zero pointer to a Dict of attribute/value pairs for
    this node. The Dict may be empty if no attributes were specified. */

Dict< String > * HtmlNode::attributes() const
{
    return &d->attributes;
}


/*! Returns this node's tag, as specified to the constructor. */

String HtmlNode::tag() const
{
    return d->tag;
}


/*! Sets this node's tag to \a s. */

void HtmlNode::setTag( const String & s )
{
    d->tag = s;
}


/*! Returns this node's text, as specified with setText(). Returns an
    empty string if this node contains no text. */

UString & HtmlNode::text() const
{
    return d->text;
}


/*! Sets this node's text() to \a s. */

void HtmlNode::setText( const UString & s )
{
    d->text = s;
}


/*! Returns this node's HTML/CSS class, as specified with
    setHtmlClass(). Returns an empty string if the node's
    class is not explicitly specified. */

String HtmlNode::htmlclass() const
{
    return d->htmlclass;
}


/*! Sets this node's htmlclass() to \a s. */

void HtmlNode::setHtmlClass( const String & s )
{
    d->htmlclass = s;
}


/*! Returns this node's HREF value, as specified with setHref(). Returns
    an empty string if the node is not a link. */

String HtmlNode::href() const
{
    return d->href;
}


/*! Sets this node's href() value to \a s. */

void HtmlNode::setHref( const String & s )
{
    d->href = s;
}


/*! Returns true if this node's tag() is recognised by the parser, and
    false otherwise. */

bool HtmlNode::isKnown() const
{
    String tag( d->tag );
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


/*! Returns true if this node is an block element, false otherwise. */

bool HtmlNode::isBlock() const
{
    if ( d->tag == "br" ||
         d->tag == "hr" )
        return false;
    if ( isKnown() )
        return true;
    return false;
}


/*! Returns true if this node is an inline element, false otherwise. */

bool HtmlNode::isInline() const
{
    if ( d->tag == "a" ||
         d->tag == "span" ||
         d->tag == "i" || d->tag == "o" || d->tag == "u" || d->tag == "b" ||
         d->tag == "em" || d->tag == "strong" )
        return true;
    return false;
}


/*! This function cleans up the node and the tree below it.
    XXX: Should this be exported to the world?
*/

void HtmlNode::clean()
{
    // tighten up quoted matter
    if ( d->tag == "blockquote" ) {
        d->tag = "p";
        d->htmlclass = "quoted";
    }
    else if ( d->attributes.contains( "cite" ) ) {
        d->tag = "p";
        d->htmlclass = "quoted";
    }
    else if ( d->attributes.contains( "type" ) &&
              d->attributes.find( "type" )->lower() == "cite" )
    {
        d->tag = "p";
        d->htmlclass = "quoted";
    }

    // get rid of quoting prefixes
    if ( isBlock() ) {
        bool first = true;
        bool ok = false;
        UString prefix;
        List<HtmlNode>::Iterator c( children() );
        while ( c ) {
            if ( c->htmlclass() == "quoted" ) {
                List<HtmlNode>::Iterator qc( c->children() );
                while ( qc ) {
                    if ( qc->text().isEmpty() ) {
                    }
                    else if ( first ) {
                        first = false;
                        prefix = qc->text();
                    }
                    else {
                        uint i = 0;
                        UString t( qc->text() );
                        while ( i < prefix.length() &&
                                i < t.length() &&
                                prefix[i] == t[i] )
                            i++;
                        prefix.truncate( i );
                    }
                    if ( prefix.length() < qc->text().length() )
                        ok = true;
                    ++qc;
                }
            }
            ++c;
        }
        if ( ok && !prefix.isEmpty() ) {
            c = children()->first();
            while ( c ) {
                if ( c->htmlclass() == "quoted" ) {
                    List<HtmlNode>::Iterator qc( c->children() );
                    while ( qc ) {
                        qc->setText( qc->text().mid( prefix.length() ) );
                        ++qc;
                    }
                }
                ++c;
            }
        }
    }

    // some kinds of tags enclose matter we simply don't want
    if ( tag() == "script" || tag() == "style" ||
         tag() == "meta" || tag() == "head" )
    {
        d->children.clear();
        d->text.truncate();
        d->tag = "";
    }

    // identify and remove sequences of ""/<br> in paragraphs
    if ( isBlock() && !isInline() && tag() != "pre" ) {
        bool br = true;
        List<HtmlNode>::Iterator i( children() );
        // remove all <br>/whitespace after <br> or at the start
        while ( i ) {
            if ( br &&
                 ( i->tag() == "br" ||
                   ( i->tag().isEmpty() &&
                     i->text().simplified().isEmpty() ) ) ) {
                d->children.take( i );
            }
            else {
                if ( i->tag() == "br" )
                    br = true;
                else
                    br = false;
                ++i;
            }
        }

        // ... ditto before the end
        while ( !d->children.isEmpty() && 
                ( d->children.last()->tag() == "br" ||
                  ( d->children.last()->tag().isEmpty() &&
                    d->children.last()->text().simplified().isEmpty() ) ) )
            d->children.take( d->children.last() );
    }

    // identify <div><div><div> ... </div></div></div> and remove the
    // inner divs.
    if ( tag() == "div" ) {
        while ( d->children.count() == 1 &&
                d->children.first()->tag() == tag() )
        {
            HtmlNode * c = d->children.first();
            d->children.clear();
            List<HtmlNode>::Iterator i( c->children() );
            while ( i ) {
                d->children.append( i );
                i->d->parent = this;
                ++i;
            }
            if ( htmlclass().isEmpty() )
                d->htmlclass = c->htmlclass();
        }
    }

    // identify signatures
    if ( parent() && htmlclass().isEmpty() && tag() == "p" && 
         !d->children.isEmpty() )
    {
        List<HtmlNode>::Iterator i( children() );
        bool sigmarker = false;
        while ( i && !sigmarker ) {
            UString t = i->text();
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
            List<HtmlNode>::Iterator i( parent()->children() );
            while ( i && i != this )
                ++i;
            if ( i == this ) {
                uint c = 0;
                List<HtmlNode>::Iterator n = i;
                while ( n && n->htmlclass().isEmpty() ) {
                    c++;
                    ++n;
                }
                if ( c < 4 &&
                     ( !n || n->htmlclass() == "quoted" ) )
                {
                    HtmlNode * div = new HtmlNode( parent(), "div" );
                    div->d->htmlclass = "signature";
                    while ( i && i != n ) {
                        div->d->children.append( i );
                        i->d->parent = div;
                        d->parent->d->children.take( i ); // moves i
                    }
                }
            }
        }
    }

    // todo: mark the last line before a quoted block if it seems
    // to be "x y schrieb"

    // mark "---original message---" and subsequent as quoted matter.
    if ( parent() && htmlclass().isEmpty() && tag() == "p" && 
         !d->children.isEmpty() )
    {
        UString t( d->children.first()->text() );
        if ( t == "-----Original Message-----" ) {
            List<HtmlNode>::Iterator i( parent()->children() );
            while ( i && i != this )
                ++i;
            if ( i == this ) {
                while ( i && i->isBlock() && i->htmlclass().isEmpty() ) {
                    i->d->htmlclass = "quoted";
                    ++i;
                }
            }
        }
    }

    // todo: identify disclaimers

    // todo: identify ascii art and mark it as <pre> or something.

    // todo: identify leading greeting and mark it

    // process children
    List<HtmlNode>::Iterator i( children() );
    while ( i ) {
        HtmlNode * n = i;
        ++i;
        n->clean();
    }

    // finally, if that left this node effectively empty, remove it entirely
    if ( parent() && 
         ( ( tag().isEmpty() && text().simplified().isEmpty() ) ||
           ( isBlock() && d->children.isEmpty() ) ) )
    {
        List<HtmlNode>::Iterator i( parent()->children() );
        while ( i && i != this )
            ++i;
        if ( i )
            parent()->d->children.take( i );
    }
}


/*! Appends one or more excerpts from this node's text() and its
    children() to \a excerpts. */

void HtmlNode::findExcerpt( UStringList * excerpts ) const
{
    if ( parent() && !htmlclass().isEmpty() ) {
        if ( excerpts->isEmpty() || !excerpts->last()->isEmpty() )
            excerpts->append( new UString );
        return;
    }
    UString r = text().simplified();
    if ( r.isEmpty() && ( tag() == "hr" || tag() == "br" ) )
        r.append( "\n" );
    excerpts->last()->append( r );
    List<HtmlNode>::Iterator i( children() );
    while ( i ) {
        i->findExcerpt( excerpts );
        ++i;
    }
    if ( isBlock() && !isInline() && !excerpts->last()->isEmpty() )
        excerpts->last()->append( "\n\n" );
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


/*! Returns a textual representation of this node. */

String HtmlNode::rendered() const
{
    String r;
    bool pre = false;
    const HtmlNode * p = this;
    while ( p && p->tag() != "pre" )
        p = p->parent();
    if ( p && p->tag() == "pre" )
        pre = true;
    if ( isBlock() ) {
        String n;
        if ( tag() != "a" && isKnown() )
            n = tag();
        if ( !n.isEmpty() ) {
            r.append( "<" );
            r.append( n );
            String htmlClass( htmlclass() );
            if ( !htmlClass.isEmpty() ) {
                r.append( " class=" );
                if ( htmlClass.boring() )
                    r.append( htmlClass );
                else
                    r.append( htmlClass.quoted() );
            }
            r.append( ">" );
            if ( !pre && !isInline() )
                r.append( "\n" );
        }
        bool contents = false;
        List<HtmlNode>::Iterator i( children() );
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
                else if ( i->isInline() )
                    lfbefore = false;
                else if ( i->isBlock() )
                    lfbefore = true;
                else if ( isInline() )
                    lfbefore = false;
                else if ( !i->tag().isEmpty() )
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
            if ( !pre && !isInline() )
                ensureTrailingLf( r );
            r.append( "</" );
            r.append( n );
            r.append( ">" );
            if ( !pre && !isInline() )
                r.append( "\n" );
        }
        if ( !contents )
            r.truncate();
    }
    else if ( !tag().isEmpty() ) {
        if ( isKnown() ) {
            r.append( "<" );
            r.append( tag() );
            r.append( ">" );
            if ( !pre )
                r.append( "\n" );
        }
    }
    else if ( !text().isEmpty() ) {
        r.reserve( text().length() );
        UString t;
        if ( pre ) {
            t = text();
        }
        else {
            t.append( 't' );
            t.append( text() );
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


/*! This private function is used by the constructor to add itself (as
    \a n) to its parent()'s list of children(). */

void HtmlNode::addChild( HtmlNode * n )
{
    d->children.append( n );
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


static UString toUnicode( class Codec * c, const String & s )
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


class HtmlParserData
    : public Garbage
{
public:
    HtmlParserData()
        : codec( 0 ), root( 0 )
    {}

    String html;
    Codec * codec;
    HtmlNode * root;
};


/*! \class HtmlParser htmlparser.h
    Parses an HTML document and provides access to the resulting tree.
*/

/*! Creates a new HtmlParser to parse \a html using \a codec. */

HtmlParser::HtmlParser( const String & html, Codec * codec )
    : d( new HtmlParserData )
{
    d->html = html;
    d->codec = codec;
    parse();
}


/*! Returns a non-zero pointer to the root node of the parse tree. */

HtmlNode * HtmlParser::rootNode() const
{
    return d->root;
}


/*! Parses the HTML document that was given to the constructor. */

void HtmlParser::parse()
{
    d->root = new HtmlNode( 0, "div" );
    d->root->setHtmlClass( "texthtml" );

    HtmlNode * t = 0;
    HtmlNode * p = d->root;
    bool seenBody = false;

    uint i = 0;
    while ( i < d->html.length() ) {
        uint j = i;
        while ( j < d->html.length() && d->html[j] != '<' )
            j++;
        if ( j > i ) {
            if ( !t ) {
                t = new HtmlNode( p );
            }
            t->text().append( toUnicode( d->codec, d->html.mid( i, j-i ) ) );
            i = j;
        }
        if ( d->html[i] == '<' ) {
            i++;
            j = i;
            while ( j < d->html.length() &&
                    d->html[j] != ' ' && d->html[j] != '>' )
                j++;

            String tag( d->html.mid( i, j-i ).lower() );

            HtmlNode * n = new HtmlNode( 0, tag );

            parseAttributes( n->attributes(), i );
            i++;

            String unwind;
            if ( tag[0] == '/' )
                unwind = tag.mid( 1 );
            else if ( tag == "p" )
                unwind = tag;
            else if ( tag == "li" )
                unwind = tag;

            if ( !unwind.isEmpty() ) {
                HtmlNode * n = t;
                if ( !n )
                    n = p;
                while ( n && n->tag() != unwind )
                    n = n->parent();
                if ( n && n->parent() ) {
                    p = n->parent();
                    t = 0;
                }
            }
            else if ( n->isBlock() && !n->isInline() ) {
                // if we see a non-line-level container tag, we close
                // the currently open line-level tags.
                HtmlNode * n = p;
                while ( n && n->isInline() )
                    n = n->parent();
                if ( n && !n->isInline() ) {
                    p = n;
                    t = 0;
                }
            }

            if ( tag[0] != '/' ) {
                n->setParent( p );
                if ( n->isBlock() )
                    p = n;
                t = 0;
            }
            if ( !seenBody && n->tag() == "body" ) {
                d->root = n;
                d->root->setTag( "div" );
                d->root->setHtmlClass( "texthtml" );
                d->root->setParent( 0 );
                seenBody = true;
            }
        }
    }
}


/*! Parses a series of name or name=value arguments in an HTML tag,
    moving \a i to the first byte after the last variable. Actually it
    skips whitespace after the last variable, too, it \a i should point
    to '>' for all wellformed html.

    Stores any attributes and values found into \a v. Silently throws
    away anything with parse errors, empty or nonexistent values, or
    other shady things.
*/

void HtmlParser::parseAttributes( Dict<String> * v, uint & i )
{
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
}
