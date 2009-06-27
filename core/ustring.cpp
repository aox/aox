// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "ustring.h"

#include "allocator.h"
#include "scope.h"
#include "estring.h"

#include "../encodings/utf.h"

#include <string.h> // strlen, memmove


/*! \class UStringData ustring.h

    This private helper class contains the actual string data. It has
    three fields, all accessible only to UString. The only noteworthy
    field is max, which is 0 in the case of a shared/read-only string,
    and nonzero in the case of a string which can be modified.
*/


/*! \fn UStringData::UStringData()

    Creates a zero-length string. This is naturally read-only.
*/

/*! Creates a new EString with \a words capacity. */

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


/*!  Constructs an empty Unicode EString. */

UString::UString()
    : Garbage(), d( 0 )
{
    // nothing more
}


/*!  Constructs an exact copy of \a other. */

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


const UString operator+( const UString & a, const UString & b )
{
    UString result;
    result.reserve( a.length() + b.length() );
    result.append( a );
    result.append( b );
    return result;
}


const UString operator+( const UString & a, const char * b )
{
    UString result;
    uint l = a.length();
    if ( b )
        l += strlen( b );
    result.reserve( l );
    result.append( a );
    result.append( b );
    return result;
}


const UString operator+( const char * a, const UString & b )
{
    return b + a;
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


/*! Appends the ASCII character sequences \a s to the end of this
    string.
*/

void UString::append( const char * s )
{
    if ( !s || !*s )
        return;
    reserve( length() + strlen( s ) );
    while ( s && *s )
        d->str[d->len++] = (uint)*s++; // I feel naughty today
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


/*! Returns true if this string contains only printable tab, cr, lf
    and ASCII characters, and false if it contains one or more other
    characters.
*/

bool UString::isAscii() const
{
    if ( isEmpty() )
        return true;
    uint i = 0;
    while ( i < d->len ) {
        if ( d->str[i] >= 128 ||
             ( d->str[i] < 32 &&
               d->str[i] != 9 && d->str[i] != 10 && d->str[i] != 13 ) )
            return false;
        i++;
    }
    return true;
}


/*! Returns a copy of this string in 7-bit ASCII. Any characters that
    aren't printable ascii are changed into '?'. (Is '?' the right
    choice?)

    This looks like AsciiCodec::fromUnicode(), but is semantically
    different. This function is for logging and debugging and may
    leave out a different set of characters than does
    AsciiCodec::fromUnicode().
*/

EString UString::ascii() const
{
    EString r;
    r.reserve( length() );
    uint i = 0;
    while ( i < length() ) {
        if ( d->str[i] >= ' ' && d->str[i] < 127 )
            r.append( (char)(d->str[i]) );
        else
            r.append( '?' );
        i++;
    }
    r.append( (char)0 );
    r.truncate( r.length() - 1 );
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


/*! Returns true if \a c is a unicode space character, and false if not. */

bool UString::isSpace( uint c )
{
    if ( c == 9 || c == 10 || c == 13 || c == 32 ||
         c == 0x00A0 || c == 0x1680 || c == 0x2002 ||
         c == 0x2003 || c == 0x2004 || c == 0x2005 ||
         c == 0x2006 || c == 0x2007 || c == 0x2008 ||
         c == 0x2009 || c == 0x200A || c == 0x200B ||
         c == 0x202F || c == 0x205F || c == 0x2060 ||
         c == 0x3000 || c == 0xFEFF )
        return true;
    return false;
}


/*! Returns a copy of this string where each run of whitespace is
    compressed to a single space character, and where leading and
    trailing whitespace is removed altogether. Most spaces are mapped
    to U+0020, but the Ogham space dominates and ZWNBSP recedes.

    Unicode space characters are as listed in
    http://en.wikipedia.org/wiki/Space_character
*/

UString UString::simplified() const
{
    // scan for the first nonwhitespace character
    uint i = 0;
    uint first = 0;
    while ( i < length() && first == i ) {
        if ( isSpace( d->str[i] ) )
            first++;
        i++;
    }

    // scan on to find the last nonwhitespace character and detect any
    // sequences of two or more whitespace characters within the
    // string.
    uint last = first;
    uint spaces = 0;
    bool identity = true;
    while ( identity && i < length() ) {
        if ( isSpace( d->str[i] ) ) {
            spaces++;
        }
        else {
            if ( spaces > 1 )
                identity = false;
            spaces = 0;
            last = i;
        }
        i++;
    }
    if ( identity )
        return mid( first, last+1-first );

    UString result;
    result.reserve( length() );
    i = 0;
    spaces = 0;
    bool ogham = false;
    bool zwnbsp = true;
    while ( i < length() ) {
        int c = d->str[i];
        if ( isSpace( c ) ) {
            if ( c == 0x1680 )
                ogham = true;
            else if ( c != 0xFEFF )
                zwnbsp = false;
            spaces++;
        }
        else {
            if ( spaces && !result.isEmpty() ) {
                if ( ogham )
                    result.append( 0x1680 );
                else if ( zwnbsp )
                    result.append( 0xFEFF );
                else
                    result.append( ' ' );
            }
            spaces = 0;
            result.append( c );
            ogham = false;
            zwnbsp = true;
        }
        i++;
    }
    return result;
}


/*! Returns a copy of this string without leading or trailing
    whitespace.
*/

UString UString::trimmed() const
{
    uint i = 0;
    uint first = length();
    uint last = 0;
    while ( i < length() ) {
        if ( !isSpace( d->str[i] ) ) {
            if ( i < first )
                first = i;
            if ( i > last )
                last = i;
        }
        i++;
    }

    if ( last >= first )
        return mid( first, last + 1 - first );

    UString empty;
    return empty;
}


/*! Returns an UTF8-encoded version of this UString. The string is
    null-terminated for easy debugging, but remember that it may also
    contain embedded nulls.
*/

EString UString::utf8() const
{
    EString s;
    Utf8Codec u;
    s = u.fromUnicode( *this );
    s.append( (char)0 );
    s.truncate( s.length() - 1 );
    return s;
}


/*! Returns -1 if this string is lexicographically before \a other, 0
    if they are the same, and 1 if this string is lexicographically
    after \a other.

    The comparison is case sensitive - just a codepoint comparison. It
    does not sort the way humans expect.
*/

int UString::compare( const UString & other ) const
{
    if ( d == other.d )
        return 0;
    uint i = 0;
    while ( i < length() && i < other.length() &&
            d->str[i] == other.d->str[i] )
        i++;
    if ( i >= length() && i >= other.length() )
        return 0;
    if ( i >= length() )
        return -1;
    if ( i >= other.length() )
        return 1;
    if ( d->str[i] < other.d->str[i] )
        return -1;
    return 1;
}


bool UString::operator<( const UString & other ) const
{
    return compare( other ) < 0;
}


bool UString::operator>( const UString & other ) const
{
    return compare( other ) > 0;
}


bool UString::operator<=( const UString & other ) const
{
    return compare( other ) <= 0;
}


bool UString::operator>=( const UString & other ) const
{
    return compare( other ) >= 0;
}


/*! Returns true if this string starts with \a prefix, and false if it
    does not.
*/

bool UString::startsWith( const UString & prefix ) const
{
    return length() >= prefix.length() &&
        prefix == mid( 0, prefix.length() );
}


/*! Returns true if this string starts with \a prefix, and false if it
    does not. \a prefix must be an ASCII or 8859-1 string.
*/

bool UString::startsWith( const char * prefix ) const
{
    if ( !prefix || !*prefix )
        return true;
    if ( !length() )
        return false;
    uint i = 0;
    while ( i < d->len && prefix[i] && prefix[i] == d->str[i] )
        i++;
    if ( i > d->len )
        return false;
    if ( prefix[i] )
        return false;
    return true;
}


/*! Returns true if this string ends with \a suffix, and false if it
    does not.
*/

bool UString::endsWith( const UString & suffix ) const
{
    return length() >= suffix.length() &&
        suffix == mid( length()-suffix.length() );
}


/*! Returns true if this string ends with \a suffix, and false if it
    does not. \a suffix must be an ASCII or 8859-1 string.
*/

bool UString::endsWith( const char * suffix ) const
{
    if ( !suffix )
        return true;
    uint l = strlen( suffix );
    if ( l > length() )
        return false;
    uint i = 0;
    while ( i < l && suffix[i] == d->str[d->len - l + i] )
        i++;
    if ( i < l )
        return false;
    return true;
}


/*! Returns the position of the first occurence of \a c on or after \a i
    in this string, or -1 if there is none.
*/

int UString::find( char c, int i ) const
{
    while ( i < (int)length() && d->str[i] != c )
        i++;
    if ( i < (int)length() )
        return i;
    return -1;
}


/*! Returns the position of the first occurence of \a s on or after \a i
    in this string, or -1 if there is none.
*/

int UString::find( const UString & s, int i ) const
{
    uint j = 0;
    while ( j < s.length() && i+j < length() ) {
        if ( d->str[i+j] == s.d->str[j] ) {
            j++;
        }
        else {
            j = 0;
            i++;
        }
    }
    if ( j == s.length() )
        return i;
    return -1;
}


/*! Returns true if this string contains at least one instance of \a s. */

bool UString::contains( const UString & s ) const
{
    if ( find( s ) >= 0 )
        return true;
    return false;
}


/*! Returns true if this string contains at least one instance of \a c. */

bool UString::contains( const char c ) const
{
    if ( find( c ) >= 0 )
        return true;
    return false;
}


/*! Returns true if this string contains at least one instance of \a s. */

bool UString::contains( const char * s ) const
{
    if ( !s || !*s )
        return true;
    int i = find( *s );
    while ( i >= 0 ) {
        uint l = strlen( s );
        uint j = 0;
        while ( j < l && i + j < length() &&
                d->str[i+j] == s[j] )
            j++;
        if ( j == l )
            return true;
        i = find( *s, i+1 );
    }
    return false;
}


#include "unicode-titlecase.inc"


/*! Returns a titlecased version of this string. Usable for
    case-insensitive comparison, not much else.
*/

UString UString::titlecased() const
{
    UString r = *this;
    uint i = 0;
    while ( i < length() ) {
        uint cp = d->str[i];
        if ( cp < numTitlecaseCodepoints &&
             titlecaseCodepoints[cp] &&
             cp != titlecaseCodepoints[cp] ) {
            r.detach();
            r.d->str[i] = titlecaseCodepoints[cp];
        }
        i++;
    }
    return r;
}


#include "unicode-isalnum.inc"


/*! Returns true if \a c is a digit, and false if not. */

bool UString::isDigit( uint c )
{
    if ( c >= numDigits )
        return false;
    return unidata[c].isDigit;
}


/*! Returns true if \a c is a letter, and false if not. */

bool UString::isLetter( uint c )
{
    if ( c >= numLetters )
        return false;
    return unidata[c].isAlpha;
}
