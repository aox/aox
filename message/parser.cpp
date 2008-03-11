// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "parser.h"

#include "ustring.h"
#include "codec.h"
#include "utf.h"


/*! \class Parser822 parser.h

    The Parser822 class provides parser help for RFC 822-like grammars.
    It properly is more like a lexer than a parser, but also not quite
    like a lexer.

    Parser822 provides a cursor, and member functions to read many
    RFC 2822 productions at the cursor. Generally, each member returns
    the production read or an empty string.
*/


/*! \fn Parser822::Parser822( const String & s )
    Creates a new RFC 822 parser object to parse \a s.
*/


/*! Returns true if \a c belongs to the RFC 2822 'atext' production, and
    false in all other circumstances.
*/

bool Parser822::isAtext( char c ) const
{
    if ( c < 32 || c > 127 )
        return false;

    if ( ( c >= 'a' && c <= 'z' ) ||
         ( c >= 'A' && c <= 'Z' ) ||
         ( c >= '0' && c <= '9' ) )
        return true;

    switch ( c ) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '/':
    case '=':
    case '?':
    case '^':
    case '_':
    case '`':
    case '{':
    case '|':
    case '}':
    case '~':
        return true;
        break;
    default:
        break;
    }

    return false;
}


/*! Moves pos() to the first nonwhitespace character after the current
    point. If pos() points to nonwhitespace
    already, it is not moved.
*/

UString Parser822::whitespace()
{
    UString out;

    char c = nextChar();
    while ( c == ' ' || c == 9 || c == 10 || c == 13 || c == 160 ) {
        out.append( c );
        step();
        c = nextChar();
    }

    return out;
}


/*! Moves pos() past all comments and surrounding white space, and
    returns the contents of the last comment.

    Returns a null string if there was no comment.
*/

String Parser822::comment()
{
    String r;
    whitespace();
    while ( present( "(" ) ) {
        r = "";
        uint commentLevel = 1;
        while( commentLevel && !atEnd() ) {
            switch( nextChar() ) {
            case '(':
                if ( commentLevel > 0 )
                    r.append( '(' );
                commentLevel++;
                break;
            case ')':
                commentLevel--;
                if ( commentLevel > 0 )
                    r.append( ')' );
                break;
            case '\\':
                step();
                r.append( nextChar() );
                break;
            default:
                r.append( nextChar() );
                break;
            }
            step();
        }
        whitespace();
        lc = r;
    }
    return r;
}


/*! Steps past an atom or a quoted-text, and returns that text. */

String Parser822::string()
{
    comment();

    // now, treat it either as a quoted string or an unquoted atom
    if ( nextChar() != '"' )
        return atom();

    String output;
    step();
    bool done = false;
    while( !done && !atEnd() ) {
        char c = nextChar();
        step();
        if ( c == '"' ) {
            done = true;
        }
        else if ( c == '\\' ) {
            output.append( nextChar() );
            step();
        }
        else if ( c == 9 || c == '\r' || c == '\n' || c == ' ' ) {
            uint wsp = pos()-1;
            whitespace();
            String t = input().mid( wsp, pos()-wsp );
            if ( t.contains( "\r" ) || t.contains( "\n" ) )
                output.append( ' ' );
            else
                output.append( t );
        }
        else {
            output.append( c );
        }
    }
    return output;
}


/*! Returns a single domain and steps past it.

    This isn't correct at the moment, but I think it will eventually be...

    Note that our definition of domain differs from the RFC 822 one. We
    only accept three forms: Something that may be a DNS A record,
    something that may be an IPv4 address in '[]' and something that may
    be an IPv6 address, again in '[]'. Examples: 'lupinella.troll.no',
    '[213.203.59.59]' and '[IPv6:::ffff:213.203.59.59]'.
*/

String Parser822::domain()
{
    String l;
    comment();
    if ( present( "[" ) ) {
        int j = pos() - 1;
        step();
        char c = nextChar();
        while ( ( c >= 'a' && c <= 'z' ) ||
                ( c >= 'A' && c <= 'Z' ) ||
                ( c >= '0' && c <= '9' ) ||
                c == '.' || c == ':' || c == '-' ) {
            step();
            c = nextChar();
        }
        require( "]" );
        l = input().mid( j, pos()-j );
    }
    else {
        l = dotAtom();
    }
    return l;
}


/*! Sets this Parser822 object to parse MIME strings if \a m is true,
    and RFC 2822 strings if \a m is false. The only difference is the
    definition of specials.
*/

void Parser822::setMime( bool m )
{
    mime = m;
}


/*! Returns a dot-atom, stepping past all relevant whitespace and
    comments.
*/

String Parser822::dotAtom()
{
    String r = atom();
    if ( r.isEmpty() )
        return r;

    bool done = false;
    while ( !done ) {
        uint m = mark();
        comment();
        require( "." );
        comment();
        String a = atom();
        if ( a.isEmpty() )
            setError( "Trailing dot in dot-atom" );
        if ( valid() ) {
            r.append( "." );
            r.append( a );
        }
        else {
            restore( m );
            done = true;
        }
    }

    return r;
}


/*! Returns a single atom, stepping past white space and comments
    before and after it.
*/

String Parser822::atom()
{
    comment();
    String output;
    while ( !atEnd() && isAtext( nextChar() ) ) {
        output.append( nextChar() );
        step();
    }
    return output;
}


/*! Returns a single MIME token (as defined in RFC 2045 section 5), which
    is an atom minus [/?=] plus [.].
*/

String Parser822::mimeToken()
{
    comment();

    String output;
    char c = nextChar();

    while ( c > 32 && c < 128 &&
            c != '(' && c != ')' && c != '<' && c != '>' &&
            c != '@' && c != ',' && c != ';' && c != ':' &&
            c != '[' && c != ']' && c != '?' && c != '=' &&
            c != '\\' && c != '"' && c != '/' )
    {
        output.append( c );
        step();
        c = nextChar();
    }

    return output;
}


/*! Returns a single MIME value (as defined in RFC 2045 section 5), which
    is an atom minus [/?=] plus [.] (i.e., a MIME token) or a quoted
    string.
*/

String Parser822::mimeValue()
{
    comment();
    if ( nextChar() == '"' )
        return string();
    return mimeToken();
}


/*! Steps past a MIME encoded-word (as defined in RFC 2047) and returns
    its decoded unicode representation, or an empty string if the cursor
    does not point to a valid encoded-word. The caller is responsible
    for checking that the encoded-word is separated from neighbouring
    tokens by whitespace.

    The characters permitted in the encoded-text are adjusted based on
    \a type, which may be Text (by default), Comment, or Phrase.
*/

UString Parser822::encodedWord( EncodedText type )
{
    // encoded-word = "=?" charset '?' encoding '?' encoded-text "?="

    //uint start = pos();

    UString r;
    String charset;
    uint m = mark();
    require( "=?" );
    if ( !valid() ) {
        restore( m );
        return r;
    }
    char c = nextChar();
    while ( c > 32 && c < 128 &&
            c != '(' && c != ')' && c != '<' && c != '>' &&
            c != '@' && c != ',' && c != ';' && c != ':' &&
            c != '[' && c != ']' && c != '?' && c != '=' &&
            c != '\\' && c != '"' && c != '/' && c != '.' )
    {
        charset.append( c );
        step();
        c = nextChar();
    }

    if ( charset.contains( '*' ) ) {
        // XXX: What should we do with the language information?
        charset = charset.section( "*", 1 );
    }

    Codec * cs = Codec::byName( charset );
    if ( !cs )
        // XXX: Should we treat unknown charsets as us-ascii?
        setError( "Unknown character set: " + charset );

    require( "?" );

    String::Encoding encoding = String::QP;
    if ( present( "q" ) )
        encoding = String::QP;
    else if ( present( "b" ) )
        encoding = String::Base64;
    else
        setError( "Unknown encoding: " + nextChar() );

    require( "?" );

    String text;
    c = nextChar();
    if ( encoding == String::Base64 ) {
        while ( ( c >= '0' && c <= '9' ) ||
                ( c >= 'a' && c <= 'z' ) ||
                ( c >= 'A' && c <= 'Z' ) ||
                c == '+' || c == '/' || c == '=' )
        {
            text.append( c );
            step();
            c = nextChar();
        }
    }
    else {
        while ( c > 32 && c < 128 && c != '?' &&
                ( type != Comment ||
                  ( c != '(' && c != ')' && c != '\\' ) ) &&
                ( type != Phrase ||
                  ( c >= '0' && c <= '9' ) ||
                  ( c >= 'a' && c <= 'z' ) ||
                  ( c >= 'A' && c <= 'Z' ) ||
                  ( c == '!' || c == '*' || c == '-' ||
                    c == '/' || c == '=' || c == '_' ||
                    c == '\'' ) ) )
        {
            text.append( c );
            step();
            c = nextChar();
        }
    }

    require( "?=" );

    // if ( pos() - start > 75 )
    //setError( "Encoded word too long (maximum permitted is 75)" );

    if ( !valid() ) {
        restore( m );
        return r;
    }
    
    if ( encoding == String::QP )
        r = cs->toUnicode( text.deQP( true ) );
    else
        r = cs->toUnicode( text.de64() );

    if ( r.contains( '\r' ) || r.contains( '\n' ) )
        r = r.simplified(); // defend against =?ascii?q?x=0aEvil:_nasty?=

    if ( r.contains( 8 ) ) { // we interpret literal DEL. fsck.
        int i = 0;
        while ( i >= 0 ) {
            i = r.find( 8, i );
            if ( i >= 0 ) {
                UString s;
                if ( i > 1 )
                    s = r.mid( 0, i - 1 );
                s.append( r.mid( i + 1 ) );
                r = s;
            }
        }
    }

    return r;
}


/*! Do RFC 2047 decoding of \a s, totally ignoring what the
    encoded-text in \a s contains.

    Depending on circumstances, the encoded-text may contain different
    sets of characters. Moreover, not every 2047 encoder obeys the
    rules. This function checks nothing, it just decodes.
*/

UString Parser822::de2047( const String & s )
{
    UString out;

    if ( !s.startsWith( "=?" ) || !s.endsWith( "?=" ) )
        return out;
    int cs = 2;
    int ce = s.find( '*', 2 );
    int es = s.find( '?', 2 ) + 1;
    if ( es < cs )
        return out;
    if ( ce < cs )
        ce = es;
    if ( ce >= es )
        ce = es-1;
    Codec * codec = Codec::byName( s.mid( cs, ce-cs ) );
    if ( s[es+1] != '?' )
        return out;
    String encoded = s.mid( es+2, s.length() - es - 2 - 2 );
    String decoded;
    switch ( s[es] ) {
    case 'Q':
    case 'q':
        decoded = encoded.deQP( true );
        break;
    case 'B':
    case 'b':
        decoded = encoded.de64();
        break;
    default:
        return out;
        break;
    }

    if ( !codec ) {
        // if we didn't recognise the codec, we'll assume that it's
        // ASCII if that would work and otherwise refuse to decode.
        AsciiCodec * a = new AsciiCodec;
        a->toUnicode( decoded );
        if ( a->wellformed() )
            codec = a;
    }

    if ( codec )
        out = codec->toUnicode( decoded );
    return out;
}


/*! Steps past a sequence of adjacent encoded-words with whitespace in
    between and returns the decoded representation. \a t passed
    through to encodedWord().

    Leading and trailing whitespace is trimmed, internal whitespace is
    kept as is.
*/

UString Parser822::encodedWords( EncodedText t )
{
    UString out;
    bool end = false;
    uint m;
    while ( !end ) {
        m = mark();
        whitespace();
        uint n = pos();
        UString us = encodedWord( t );
        if ( n == pos() )
            end = true;
        else
            out.append( us );
    }

    restore( m );
    return out.trimmed();
}


/*! Steps past the longest "*text" (a series of text/encoded-words) at
    the cursor and returns its unicode representation, which may
    be an empty string.
*/

UString Parser822::text()
{
    UString out;

    UString space( whitespace() );
    UString word;
    bool progress = true;
    while ( progress ) {
        uint m = mark();
        uint p = pos();

        bool encodedWord = false;

        if ( present( "=?" ) ) {
            restore( m );
            encodedWord = true;
            word = encodedWords();
            if ( p == pos() )
                encodedWord = false;
        }

        if ( !encodedWord ) {
            word.truncate();
            char c = nextChar();
            while ( !atEnd() && c < 128 &&
                    c != ' ' && c != 9 && c != 10 && c != 13 ) {
                word.append( c );
                step();
                c = nextChar();
            }
        }
        if ( p == pos() ) {
            progress = false;
        }
        else {
            out.append( space );
            out.append( word );

            space = whitespace();
            if ( space.contains( '\r' ) || space.contains( '\n' ) ) {
                space.truncate();
                space.append( ' ' );
            }
        }
    }

    if ( space.length() != 0 )
        out.append( space );

    return out;
}


/*! Steps past an RFC 822 phrase (a series of word/encoded-words) at the
    cursor and returns its unicode representation, which may be an
    empty string.
*/

UString Parser822::phrase()
{
    UString out;

    comment();

    bool wasEncoded = false;
    UString spaces;
    bool progress = true;

    while ( !atEnd() && progress ) {
        AsciiCodec a;
        UString t;

        bool encoded = false;
        bool h = false;
        uint p = pos();
        uint m = mark();
        if ( present( "=?" ) ) {
            restore( m );
            t = encodedWords( Phrase );
            if ( p < pos() ) {
                h = true;
                encoded = true;
            }
        }
        if ( !h && present( "\"" ) ) {
            restore( m );
            t = a.toUnicode( string() );
            if ( p < pos() )
                h = true;
        }
        if ( !h ) {
            t = a.toUnicode( atom() );
            if ( p < pos() )
                h = true;
        }

        if ( h || !t.isEmpty() ) {
            // we did read something, so we need to add it to the
            // previous word(s).

            // first, append the spaces before the word we added. RFC
            // 2047 says that spaces between encoded-words should be
            // disregarded, so we do.
            if ( !encoded || !wasEncoded )
                out.append( spaces );
            // next append the word we read
            out.append( t );
            // then read new spaces which we'll use if there is
            // another word.
            spaces = whitespace();
            // RFC violation: if the spaces included a CR/LF, we
            // properly should just get rid of the CRLF and one
            // trailing SP, but changing it all to a single space
            // matches the expectations of most senders better.
            if ( spaces.contains( '\r' ) || spaces.contains( '\n' ) ) {
                spaces.truncate();
                spaces.append( ' ' );
            }
            wasEncoded = encoded;
        }
        else {
            progress = false;
        }
    }

    return out;
}


/*! Returns the number of CFWS characters at the cursor, but does
    nothing else.
*/

int Parser822::cfws()
{
    uint m = mark();
    uint p = pos();
    comment();
    p = pos() - p;
    restore( m );
    return p;
}


/*! Skips past whitespace, parses a decimal number and returns that
    number.
*/

uint Parser822::number()
{
    comment();
    bool ok = false;
    String s = digits( 1, 15 );
    uint n = s.number( &ok );
    if ( !ok )
        setError( "number " + s + " is bad somehow" );
    return n;
}


/*! Returns the last comment seen so far by this parser, or a null
    string if none has been seen yet.
*/

String Parser822::lastComment() const
{
    return lc;
}


/*! \fn bool Parser822::isMime() const
    Returns true if this parser has been instructed to parse MIME
    strings by calling setMime(), and false otherwise.
*/

/*! \fn bool Parser822::valid()
    Returns true if this parser has not yet encountered any errors
    during parsing, and false otherwise.
*/
