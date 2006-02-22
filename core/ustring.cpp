// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "ustring.h"

#include "allocator.h"
#include "scope.h"
#include "sys.h"
#include "string.h"


/*! \class UString ustring.h
    The UString class provides a normalized Unicode string.

    At Oryx, Unicode strings are used sparingly. Unicode is the common
    character encoding for all strings except those limited to US-ASCII,
    but such strings are sparingly manipulated.

    Most of the functionality of UString is concerned with conversion
    to/from other encodings, such as ISO-8859-15, KOI-U, etc, etc. Other
    functionality is intentionally kept to a minimum, to lighten the
    testing burden.

    Two functions note particular mention are ascii() and the equality
    operator. ascii() returns something that's useful for logging, but
    which can often not be converted back to unicode.

    There is a fast equality operator which tests against printable
    ASCII, returning false for every unprintable or non-ASCII
    character. Very useful for comparing a UString to e.g. "seen" or
    ".", but nothing more.
*/


/*!  Constructs an empty Unicode String. */

UString::UString()
    : len( 0 ), max( 0 ),
      str( 0 )
{
    // nothing more
}


/*!  Constructs an exact copy of \a other on the current arena. */

UString::UString( const UString & other )
    : len( 0 ), max( 0 ),
      str( 0 )
{
    *this = other;
}


/*! Destroys the string. Doesn't free anything. */

UString::~UString()
{
    // woo.
}


/*! Makes this string into an exact copy of \a other and returns a
    reference to this strng. */

UString & UString::operator=( const UString & other )
{
    if ( other.str != str ) {
        reserve( other.len );
        memmove( str, other.str, other.len * sizeof(int) );
        len = other.len;
    }
    return *this;

}


/*! Appends \a other to this string and returns a reference to this
    strng. */

UString & UString::operator+=( const UString & other )
{
    append( other );
    return *this;
}


/*! Appends \a other to the end of this string. */

void UString::append( const UString & other )
{
    reserve( len + other.len );
    uint * dest = str + len;
    memmove( dest, other.str, other.len * sizeof(uint) );
    len += other.len;
}


/*! Appends unicode code point \a cp to the end of this string. */

void UString::append( const uint cp )
{
    reserve( len + 1 );
    str[len++] = cp;
}


/*! Ensures that at least \a size bytes are available for this
    string. Users of UString should generally not need to call this;
    it is called by append() etc. as needed.
*/

void UString::reserve( uint size )
{
    if ( max >= size )
        return;

    size = Allocator::rounded( size * sizeof( uint ) ) / sizeof( uint );
    uint * s = (uint*)Allocator::alloc( sizeof( uint ) * size, 0 );
    if ( len )
        memmove( s, str, sizeof( uint ) * len );
    str = s;
    max = size;
}


/*! Truncates this string to \a l characters. If the string is shorter,
    truncate() does nothing. If \a l is 0 (the default), the string will
    be empty after this function is called.
*/

void UString::truncate( uint l )
{
    if ( l < len )
        len = l;
}


/*! Returns a copy of this string in 7-bit ASCII. Any characters that
    aren't printable ascii are changed into '?'. (Is '?' the right
    choice?)

    This looks like AsciiCodec::fromUnicode(), but is semantically
    different. This function is for logging and debugging and may
    leave out a different set of characters than does
    AsciiCodec::fromUnicode().
*/

String UString::ascii() const
{
    String r;
    r.reserve( len );
    uint i = 0;
    while ( i < len ) {
        if ( str[i] >= ' ' && str[i] < 127 )
            r.append( (char)str[i] );
        else
            r.append( '?' );
        i++;
    }
    return r;
}


/*! Returns a string containing the data starting at position \a start
    of this string, extending for \a num bytes. \a num may be left out,
    in which case the rest of the string is returned.

    If \a start is too large, an empty string is returned.
*/

UString UString::mid( uint start, uint num ) const
{
    UString r;

    uint i = start;
    r.reserve( num );
    while ( i < len && i-start < num ) {
        r.append( str[ i ] );
        i++;
    }

    return r;
}


/*! Returns the number encoded by this string, and sets \a *ok to true
    if that number is valid, or to false if the number is invalid. By
    default the number is encoded in base 10, if \a base is specified
    that base is used. \a base must be at least 2 and at most 36.

    If the number is invalid (e.g. negative), the return value is undefined.

    If \a ok is a null pointer, it is not modified.
*/

uint UString::number( bool * ok, uint base ) const
{
    uint i = 0;
    uint n = 0;

    bool good = !isEmpty();
    while ( good && i < len ) {
        if ( str[i] < '0' || str[i] > 'z' )
            good = false;

        uint digit = str[i] - '0';

        // hex or something?
        if ( digit > 9 ) {
            uint c = str[i];
            if ( c > 'Z' )
                c = c - 32;
            digit = c - 'A' + 10;
        }

        // is the digit too large?
        if ( digit >= base )
            good = false;

        // Would n overflow if we multiplied by 10 and added digit?
        if ( n > UINT_MAX/base )
            good = false;
        n *= base;
        if ( n >= (UINT_MAX - UINT_MAX % base) && digit > (UINT_MAX % base) )
            good = false;
        n += digit;

        i++;
    }

    if ( ok )
        *ok = good;

    return n;
}


/*! Modifies this string so that all linefeeds are CRLF, and so that
    the string ends with CRLF.
*/

void UString::useCRLF()
{
    bool needed = false;
    if ( len < 2 || str[len-1] != 10 || str[len-2] != 13 )
        needed = true;
    uint i = 0;
    while ( !needed && i < len ) {
        if ( str[i] == 10 ) {
            needed = true;
        }
        else if ( str[i] == 13 ) {
            if ( i < len-1 && str[i+1] == 10 )
                i++;
            else
                needed = true;
        }
        i++;
    }
    if ( !needed )
        return;

    i = 0;
    uint l = 0;
    while ( i < len ) {
        if ( str[i] == 10 || str[i] == 13 )
            l++;
        i++;
    }

    uint * prev = str;
    uint plen = len;
    str = 0;
    max = 0;
    len = 0;

    reserve( plen + 2 * l + 2 );
    i = 0;
    len = 0;
    while ( i < plen ) {
        bool lf = false;
        if ( prev[i] == 13 && i < plen-1 && prev[i+1] == 10 ) {
            i++;
            lf = true;
        }
        else if ( prev[i] == 13 || prev[i] == 10 ) {
            lf = true;
        }

        if ( lf ) {
            str[len++] = 13;
            str[len++] = 10;
        }
        else {
            str[len++] = prev[i];
        }
        i++;
        if ( i == plen && !lf ) {
            str[len++] = 13;
            str[len++] = 10;
        }
    }
}
