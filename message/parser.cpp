// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "parser.h"

#include "ustring.h"
#include "codec.h"


/*! \class Parser822 parser.h

    The Parser822 class provides parser help for RFC822-like grammars.
    It properly is more like a lexer than a parser, but also not quite
    like a lexer.

    Parser822 provides a cursor, and member functions to read many
    RFC2822 productions at the cursor. Generally, each member returns
    the production read or an empty string.
*/


/*! \fn Parser822::Parser822( const String & s )
    Creates a new RFC822 parser object to parse \a s.
*/


/*! Returns true if \a c belongs to the RFC2822 'atext' production, and
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


/*! Asserts that the index points at \a expect and steps past it. If the
    index doesn't, \a errorMessage is logged.

    If \a expect has length 0, this function is a noop.
*/

void Parser822::stepPast( const char * expect, const char * errorMessage )
{
    if ( !expect || !*expect )
        return;
    int j = 0;
    while ( expect[j] != 0 && s[i+j] == expect[j] )
        j++;
    if ( expect[j] )
        error( errorMessage );
    else
        i = i + j;
}


/*! Moves index() to the first nonwhitespace character after the current
    point. If index() points to nonwhitespace already, it is not moved.
*/

void Parser822::whitespace()
{
    while ( i < s.length() &&
            ( s[i] == ' ' || s[i] == 9 || s[i] == 10 || s[i] == 13 ) )
        i++;
}


/*! \fn uint Parser822::index() const
    Returns the current position of the parser cursor. This is 0 at the
    start, and advances as characters are parsed.
*/


/*! Moves index() past all comments and surrounding white space, and
    returns the contents of the last comment.

    Returns a null string if there was no comment.
*/

String Parser822::comment()
{
    String r;
    whitespace();
    while ( s[i] == '(' ) {
        r = "";
        uint commentLevel = 0;
        do {
            switch( s[i] ) {
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
                r.append( s[++i] );
                break;
            default:
                r.append( s[i] );
                break;
            }
            i++;
        } while( commentLevel && i < s.length() );
        whitespace();
    }
    return r;
}


/*! Steps past an atom or a quoted-text, and returns that text. */

String Parser822::string()
{
    comment();

    // now, treat it either as a quoted string or an unquoted atom
    if ( s[i] != '"' )
        return atom();

    String output;
    i++;
    bool done = false;
    while( !done && i < s.length() ) {
        if ( s[i] == '"' ) {
            i++;
            done = true;
        }
        else if ( s[i] == '\\' ) {
            output.append( s[++i] );
            i++;
        }
        else if ( s[i] == 32 || s[i] == 9 || s[i] == 10 || s[i] == 13 ) {
            // this is strictly speaking wrong. CRLF should be killed,
            // all others left alone.
            output.append( ' ' );
            whitespace();
        }
        else {
            output.append( s[i++] );
        }
    }
    return output;
}


/*! Returns a run of strings, with separating spaces. */

String Parser822::phrase()
{
    String r = string();
    if ( r.isEmpty() )
        return r;

    String w = string();
    while ( !w.isEmpty() ) {
        r = r + " " + w;
        w = string();
    };

    return r;
}


/*! Returns a single character and steps to the next. */

char Parser822::character()
{
    return s[i++];
}


/*! Returns a single domain and steps past it.

    This isn't correct at the moment, but I think it will eventually be...

    Note that our definition of domain differs from the RFC822 one. We
    only accept three forms: Something that may be a DNS A record,
    something that may be an IPv4 address in '[]' and something that may
    be an IPv6 address, again in '[]'. Examples: 'lupinella.troll.no',
    '[213.203.59.59]' and '[IPv6:::ffff:213.203.59.59]'.
*/

String Parser822::domain()
{
    String l;
    comment();
    if ( next() == '[' ) {
        int j = i;
        step();
        char c = s[i];
        while ( ( c >= 'a' && c <= 'z' ) ||
                ( c >= 'A' && c <= 'Z' ) ||
                ( c >= '0' && c <= '9' ) ||
                c == '.' || c == ':' || c == '-' ) {
            step();
            c = next();
        }
        if ( next() == ']' )
            step();
        else
            error( "missing trailing ']' ([1.2.3.4])" );
        l = s.mid( j, i-j );
    }
    else {
        l = dotAtom();
    }
    return l;
}


/*! Sets this Parser822 object to parse MIME strings if \a m is true,
    and RFC2822 strings if \a m is false. The only difference is the
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

    bool m = true;
    comment();
    while ( m && s[i] == '.' ) {
        int j = i;
        i++;
        String a = atom();
        if ( a.isEmpty() ) {
            i = j; // backtrack to the dot
            m = false;
        }
        else {
            r = r + "." + a;
            comment();
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
    while ( i < s.length() && isAtext( s[i] ) )
        output.append( s[i++] );
    return output;
}


/*! Returns a single MIME token (as defined in RFC2045, §5), which is an
    atom minus [/?=] plus [.].
*/

String Parser822::mimeToken()
{
    String output;
    char c = s[i];

    while ( i < s.length() &&
            c > 32 && c < 128 &&
            c != '(' && c != ')' && c != '<' && c != '>' &&
            c != '@' && c != ',' && c != ';' && c != ':' &&
            c != '[' && c != ']' && c != '?' && c != '=' &&
            c != '\\' && c != '"' && c != '/' )
    {
        output.append( c );
        i++;
        c = s[i];
    }

    return output;
}


/*! Returns a single MIME value (as defined in RFC2045, §5), which is an
    atom minus [/?=] plus [.] (i.e., a MIME token) or a quoted string.
*/

String Parser822::mimeValue()
{
    if ( s[i] == '"' )
        return string();
    return mimeToken();
}


/*! Steps past a MIME encoded-word (as defined in RFC2047 and updated by
    RFC2231) and returns its decoded representation, or an empty string
    if the cursor does not point to a valid encoded-word. This function
    does not check that encoded-words are correctly separated from any
    neighbouring tokens by whitespace: the caller must verify that.

    The characters permitted in the encoded-text are adjusted based on
    \a type, which may be Text (by default), Comment, or Phrase.
*/

UString Parser822::encodedWord( EncodedText type )
{
    UString out;

    // encoded-word = "=?" charset '?' encoding '?' encoded-text "?="

    int n = i;
    Codec *cs = 0;
    bool valid = true;
    String charset, encoding, text;

    if ( s[n] != '=' || s[++n] != '?' )
        valid = false;

    if ( valid ) {
        int m = ++n;
        char c = s[m];
        while ( m - i <= 75 &&
                c > 32 && c < 128 &&
                c != '(' && c != ')' && c != '<' && c != '>' &&
                c != '@' && c != ',' && c != ';' && c != ':' &&
                c != '[' && c != ']' && c != '?' && c != '=' &&
                c != '\\' && c != '"' && c != '/' && c != '.' )
        {
            charset.append( c );
            c = s[++m];
        }

        // XXX: Should we treat unknown charsets as us-ascii?
        int j = charset.find( '*' );
        if ( j > 0 ) {
            // XXX: What should we do with the language information?
            charset = charset.mid( 0, j );
        }

        if ( m - i > 75 || ( cs = Codec::byName( charset ) ) == 0 )
            valid = false;
        else
            n = m;
    }

    if ( valid && s[n] != '?' )
        valid = false;

    if ( valid ) {
        int m = ++n;
        char c = s[m];
        while ( m - i <= 75 &&
                c > 32 && c < 128 &&
                c != '(' && c != ')' && c != '<' && c != '>' &&
                c != '@' && c != ',' && c != ';' && c != ':' &&
                c != '[' && c != ']' && c != '?' && c != '=' &&
                c != '\\' && c != '"' && c != '/' && c != '.' )
        {
            encoding.append( c );
            c = s[++m];
        }

        encoding = encoding.lower();
        if ( m - i > 75 || ( encoding != "q" && encoding != "b" ) )
            valid = false;
        else
            n = m;
    }

    if ( valid && s[n] != '?' )
        valid = false;

    if ( valid ) {
        int m = ++n;
        char c = s[m];
        while ( m - i <= 75 &&
                c > 32 && c < 128 && c != '?' &&
                ( type != Comment ||
                  ( c != '(' && c != ')' && c != '\\' ) ) && 
                ( type != Phrase || 
                  ( ( c >= '0' && c <= '9' ) ||
                    ( c >= 'a' && c <= 'z' ) ||
                    ( c >= 'A' && c <= 'Z' ) ||
                    ( c == '!' || c == '*' || c == '-' ||
                      c == '/' || c == '=' || c == '_' ) ) ) )
        {
            text.append( c );
            c = s[++m];
        }

        if ( m - i > 75 )
            valid = false;
        else
            n = m;
    }

    if ( valid && ( s[n] != '?' || s[++n] != '=' ) )
        valid = false;

    if ( valid ) {
        if ( encoding == "q" )
            text = text.deQP( true );
        else if ( encoding == "b" )
            text = text.de64();
        out = cs->toUnicode( text );
        i = ++n;
    }

    return out;
}


/*! Steps past the longest "*text" (a series of text/encoded-words) at
    the cursor, and returns its decoded representation, which may be an
    empty string.
*/

UString Parser822::text()
{
    UString out;

    uint first = i;
    bool sawEncoded = false;

    char c = s[i];
    while ( i < s.length() &&
            c != 0 && c != '\012' && c != '\015' )
    {
        if ( ( c == ' ' && s[i+1] == '=' && s[i+2] == '?' ) ||
             ( i == first && s[i] == '=' && s[i+1] == '?' ) )
        {
            if ( c == ' ' )
                c = s[++i];
            if ( !sawEncoded && i != first )
                out.append( ' ' );
            uint n = i;
            UString us = encodedWord();
            if ( !us.isEmpty() &&
                 ( s[i] == ' ' || s[i] == '\012' || s[i] == '\015' ||
                   i == s.length() ) )
            {
                sawEncoded = true;
                out.append( us );
                c = s[i];
            }
            else {
                i = n;
            }
        }
        else {
            sawEncoded = false;
        }

        if ( !sawEncoded ) {
            out.append( c );
            c = s[++i];
        }
    }

    return out;
}
