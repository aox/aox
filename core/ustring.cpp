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
    truncate() does nothing.
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


