// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "parser.h"


/*! \class Parser parser.h

  The Parser class does basic C++ parsing.

  It doesn't actually parse C++: all it does is lend some support to
  the header and source handling, which needs to find certain
  constructs and look at them.
*/


/*! Constructs a Parser for string \a s. The parser's cursor is left
    at the beginning of \a s. */

Parser::Parser( const String & s )
    : t( s ), i( 0 )
{
    // nothing necessary
}


/*! Returns true if the parser has reached the end of its input, and
    false if not.
*/

bool Parser::atEnd() const
{
    return i >= t.length();
}


/*! Returns the parser's current line number.

The line number is that of the first unparsed nonwhitespace
character. This implies that if the parser's cursor is at the end of a
line, then the line number returned is that of the next nonempty line.
*/

uint Parser::line() const
{
    uint l = 1;
    uint j = 0;
    while ( j < i ||
            ( t[j] == 32 || t[j] == 9 || t[j] == 13 || t[j] == 10 ) ) {
        if ( t[j] == 10 )
            l++;
        j++;
    }
    return l;
}


/*! Scans forward until an instance of \a text is found, and positions
    the cursor at the first character after that string. */

void Parser::scan( const String & text )
{
    uint j = 0;
    while ( i < t.length() && j < text.length() ) {
        j = 0;
        while ( j < text.length() && t[i+j] == text[j] )
            j++;
        if ( j < text.length() )
            i++;
    }
    if ( j == text.length() )
        i += j;
}


/*! Scans for \a text and returns all the text, without the trailing
    instance of \a text. The cursor is left after \a text. */

String Parser::textUntil( const String & text )
{
    uint j = i;
    scan( text );
    if ( atEnd() )
        return t.mid( j, i-j );
    return t.mid( j, i-j-text.length() );
}


/*! Scans past whitespace, leaving the cursor at the end or at a
    nonwhitespace character.
*/

void Parser::whitespace()
{
    i = whitespace( i );
}


static String spaceless( const String & t )
{
    uint i = 0;
    String r;
    while ( i < t.length() ) {
        if ( t[i] != 32 && t[i] != 9 && t[i] != 13 && t[i] != 10 )
            r.append( t[i] );
        i++;
    }
    return r;
}


/*! Returns the C++ identifier at the cursor, or an empty string if
    there isn't any. Steps past the identifier and any trailing whitespace.
*/

String Parser::identifier()
{
    int j = complexIdentifier( i );
    String r = spaceless( t.mid( i, j - i ) );
    i = j;
    return r;
}


/*! Scans past the simpler identifier starting at \a j, returning the
    first position afte the identifier. If something goes wrong,
    simpleIdentifier() returns \a j.

    A simple identifier is a text label not containing ::, <, >,
    whitespace or the like.
*/

uint Parser::simpleIdentifier( uint j )
{
    uint k = whitespace( j );
    if ( ( t[k] >= 'A' && t[k] <= 'z' ) ||
         ( t[k] >= 'a' && t[k] <= 'z' ) ) {
        j = k + 1;
        while ( ( t[j] >= 'A' && t[j] <= 'z' ) ||
                ( t[j] >= 'a' && t[j] <= 'z' ) ||
                ( t[j] >= '0' && t[j] <= '9' ) ||
                ( t[j] == '_' ) )
            j++;
    }
    return j;
}


/*! Scans past the complex identifier starting at \a j, returning the
    first position after the identifier. If something goes wrong,
    complexIdentifier() returns \a j.

    A complex identifier is anything that may be used as an identifier
    in C++, even "operator const char *".
*/

uint Parser::complexIdentifier( uint j )
{
    uint k = simpleIdentifier( j );
    if ( k == j )
        return j;
    j = whitespace( k );

    while ( t[j] == ':' && t[j+1] == ':' ) {
        if ( t.mid( j+2, 8 ) == "operator" )
            j = operatorHack( j+2 );
        else if ( t[j+2] == '~' )
            j = simpleIdentifier( j + 3 );
        else
            j = simpleIdentifier( j + 2 );
    }

    j = whitespace( j );
    if ( t[j] == '<' ) {
        k = complexIdentifier( j + 1 );
        if ( k > j + 1 && t[k] == '>' )
            j = k+1;
    }
    return j;
}


/*! Parses a type name starting at \a j and returns the first
    character after the type name (and after trailing whitespace). If
    a type name can't be parsed, \a j is returned.
*/

uint Parser::type( uint j )
{
    // first, we have zero or more of const, static etc.
    uint l = j;
    uint k;
    do {
        k = l;
        l = whitespace( k );
        while ( t[l] >= 'a' && t[l] <= 'z' )
            l++;
        String modifier = t.mid( k, l-k ).simplified();
        if ( !( modifier == "const" ||
                modifier == "inline" ||
                modifier == "unsigned" ||
                modifier == "signed" ||
                modifier == "class" ||
                modifier == "struct" ||
                modifier == "virtual" ||
                modifier == "static" ) )
            l = k;
    } while ( l > k );

    l = complexIdentifier( k );
    if ( l == k )
        return j;

    k = whitespace( l );
    if ( t[k] == ':' && t[k+1] == ':' ) {
        l = whitespace( simpleIdentifier( k+2 ) );
        if ( l == k )
            return j;
        k = l;
    }

    if ( t[k] == '&' || t[k] == '*' )
        k = whitespace( k + 1 );
    return k;
}


/*! Parses a type specifier and returns it as a string. If the cursor
    doesn't point to one, type() returns an empty string.

*/

String Parser::type()
{
    uint j = type( i );
    String r = t.mid( i, j-i ).simplified(); // simplified() is not quite right
    i = j;
    return r;
}


/*! Parses an argument list (for a particularly misleading meaning of
    parse) and returns it. The cursor must be on the leading '(', it
    will be left immediately after the trailing ')'.

    The argument list is returned including parentheses. In case of an
    error, an empty string is returned and the cursor is left near the
    error.
*/

String Parser::argumentList()
{
    String r;
    uint j = whitespace( i );
    if ( t[j] != '(' )
        return r;
    r = "( ";
    i = whitespace( j + 1 );
    if ( t[i] == ')' ) {
        i++;
        return "()";
    }
    String s = "";
    bool more = true;
    while ( more ) {
        String tp = type();
        if ( tp.isEmpty() )
            return ""; // error message here?
        whitespace();
        j = simpleIdentifier( i );
        if ( j > i ) { // there is a variable name
            tp = tp + " " + t.mid( i, j-i ).simplified();
            i = j;
        }
        r = r + s + tp;
        whitespace();
        if ( t[i] == '=' ) { // there is a default value...
            while ( i < t.length() && t[i] != ',' && t[i] != ')' )
                i++;
            whitespace();
        }
        s = ", ";
        if ( t[i] == ',' ) {
            more = true;
            i++;
        }
        else {
            more = false;
        }
    }
    if ( t[i] != ')' )
        return "";
    r.append( " )" );
    i++;
    return r;
}


/*! Steps the Parser past one character. */

void Parser::step()
{
    i++;
}


/*! Returns true if the first unparsed characters of the string are
    the same as \a pattern, and false if not. */

bool Parser::lookingAt( const String & pattern )
{
    return t.mid( i, pattern.length() ) == pattern;
}


/*! Parses and steps past a single word. If the next nonwhitespace
    character is not a word character, this function returns an empty
    string.
*/

String Parser::word()
{
    uint j = simpleIdentifier( i );
    while ( t[j] == '-' ) {
        uint k = simpleIdentifier( j+1 );
        if ( k > j + 1 )
            j = k;
    }
    String r = t.mid( i, j-i ).simplified();
    if ( !r.isEmpty() )
        i = j;
    return r;
}


/*! Steps past the whitespace starting at \a j and return the index of
    the first following nonwhitespace character.
*/

uint Parser::whitespace( uint j )
{
    bool again = true;
    while ( again ) {
        again = false;

        while ( t[j] == 32 || t[j] == 9 || t[j] == 13 || t[j] == 10 )
            j++;

        if ( t[j] == '/' && t[j+1] == '/' ) {
            while( j < t.length() && t[j] != '\n' )
                j++;
            again = true;
        }
    }
    return j;
}


/*! Reads past an operator name starting at \a j and returns the index
    of the following characters. If \a j does not point to an operator
    name, operatorHack() returns \a j.
*/

uint Parser::operatorHack( uint j )
{
    uint i, k = j+8;
    k = whitespace( k );

    // Four possible cases: We're looking at a single character, two
    // characters, '()', or "String".

    uint chars = 0;

    if ( t[k] == '(' && t[k+1] == ')' ) {
        chars = 2;
    }
    else if ( ( ( t[k] > ' ' && t[k] < '@' ) ||
                  ( t[k] > 'Z' && t[k] < 'a' ) ) &&
                !( t[k] >= '0' && t[k] <= '9' ) ) {
        chars = 1;
        if ( t[k+1] != '(' &&
             ( ( t[k+1] > ' ' && t[k+1] < '@' ) ||
               ( t[k] > 'Z' && t[k] < 'a' ) ) &&
             !( t[k+1] >= '0' && t[k+1] <= '9' ) )
            chars = 2;
    }
    else if ( ( i = type( k ) ) > k ) {
        chars = i-k;
    }

    if ( chars > 0 ) {
        k = whitespace( k+chars );
        if ( t[k] == '(' )
            return k;
    }
    return j;
}
