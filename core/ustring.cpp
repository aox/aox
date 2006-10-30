// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "ustring.h"

#include "allocator.h"
#include "scope.h"
#include "sys.h"
#include "string.h"


/*! \class UStringData ustring.h

    This private helper class contains the actual string data. It has
    three fields, all accessible only to UString. The only noteworthy
    field is max, which is 0 in the case of a shared/read-only string,
    and nonzero in the case of a string which can be modified.
*/


/*! \fn UStringData::UStringData()

    Creates a zero-length string. This is naturally read-only.
*/

/*! Creates a new String with \a words capacity. */

UStringData::UStringData( int words )
    : str( 0 ), len( 0 ), max( words )
{
    if ( str )
        str = (uint*)Allocator::alloc( words*sizeof(uint), 0 );
}


void * UStringData::operator new( size_t ownSize, uint extra )
{
    return Allocator::alloc( ownSize + extra*sizeof(uint), 1 );
}



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
    : Garbage(), d( 0 )
{
    // nothing more
}


/*!  Constructs an exact copy of \a other on the current arena. */

UString::UString( const UString & other )
    : Garbage(), d( new UStringData )
{
    *this = other;
}


/*! Destroys the string. Doesn't free anything. */

UString::~UString()
{
    if ( d && d->max )
        Allocator::dealloc( d );
    d = 0;
}


/*! Deletes \a p. (This function exists only so that gcc -O3 doesn't
    decide that UString objects don't need destruction.)
*/

void UString::operator delete( void * p )
{
    UStringData * & d = ((UString *)p)->d;
    if ( d && d->max )
        Allocator::dealloc( d );
    d = 0;
}




/*! Makes this string into an exact copy of \a other and returns a
    reference to this strng. */

UString & UString::operator=( const UString & other )
{
    d = other.d;
    if ( d )
        d->max = 0;
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
    if ( !other.length() )
        return;
    if ( !length() && ( !modifiable() || d->max < other.length() ) ) {
        // if this isn't modifiable, we just make a copy of the other
        // string. only sensible thing to do. if it's modifiable, but
        // we don't have enough bytes, we also just glue ourselves
        // onto the other. maybe we'll need to copy later, but maybe
        // not.
        *this = other;
        return;
    }
    reserve( length() + other.length() );
    memmove( d->str+d->len, other.d->str, sizeof(uint)*other.d->len );
    d->len += other.d->len;
}


/*! Appends unicode code point \a cp to the end of this string. */

void UString::append( const uint cp )
{
    reserve( length() + 1 );
    d->str[d->len] = cp;
    d->len++;
}


/*! Ensures that at least \a num characters are available for this
    string. Users of UString should generally not need to call this;
    it is called by append() etc. as needed.
*/

void UString::reserve( uint num )
{
    if ( !num )
        num = 1;
    if ( !d || d->max < num )
        reserve2( num );
}


/*! Equivalent to reserve(). reserve( \a num ) calls this function to
    do the heavy lifting. This function is not inline, while reserve()
    is, and calls to this function should be interesting wrt. memory
    allocation statistics.

    Noone except reserve() should call reserve2().
*/

void UString::reserve2( uint num )
{
    const uint std = sizeof( UStringData );
    const uint si = sizeof( uint );
    num = ( Allocator::rounded( num * si + std ) - std ) / si;

    UStringData * freeable = 0;
    if ( d && d->max )
        freeable = d;

    UStringData * nd = new( num ) UStringData( 0 );
    nd->max = num;
    nd->str = (uint*)(std + (char*)nd);
    if ( d )
        nd->len = d->len;
    if ( nd->len > num )
        nd->len = num;
    if ( d && d->len )
        memmove( nd->str, d->str, nd->len*si );
    d = nd;

    if ( freeable )
        Allocator::dealloc( freeable );
}


/*! Truncates this string to \a l characters. If the string is shorter,
    truncate() does nothing. If \a l is 0 (the default), the string will
    be empty after this function is called.
*/

void UString::truncate( uint l )
{
    if ( l < length() ) {
        detach();
        d->len = l;
    }
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
    r.reserve( length() );
    uint i = 0;
    while ( i < length() ) {
        if ( d->str[i] >= ' ' && d->str[i] < 127 )
            r.append( (char)(d->str[i]) );
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
    if ( !d )
        num = 0;
    else if ( num > d->len || start + num > d->len )
        num = d->len - start;

    UString result;
    if ( !num || start >= length() )
        return result;

    d->max = 0;
    result.d = new UStringData;
    result.d->str = d->str + start;
    result.d->len = num;
    return result;
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
    return ascii().number( ok, base );
}
