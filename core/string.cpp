// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "string.h"

#include "allocator.h"
#include "sys.h"

// stderr, fprintf
#include <stdio.h>


/*! \class StringData string.h

    This private helper class contains the actual string data. It has
    three fields, all accessible only to string. The only noteworthy
    field is max, which is 0 in the case of a shared/read-only string,
    and nonzero in the case of a string which can be modified.
*/


/*! \fn StringData::StringData()

    Creates a zero-length string. This is naturally read-only.
*/

/*! Creates a new String with \a bytes capacity. */

StringData::StringData( int bytes )
    : str( 0 ), len( 0 ), max( bytes )
{
    str = (char*)Allocator::alloc( max, 0 );
}




/*! \class String string.h
    A generic 8-bit string class.

    The string data are counted, so null bytes are allowed, and most
    operations are very fast.

    The data structure uses a simplifed variant of reference counting,
    where only "one" and "many" are possible. The detach() function
    ensures that the count is "one" afterwards. Many functions leave
    the count on "many", even ones such as mid().

    Only a small set of core operations are so far implemented,
    including length(), cstr() (to convert to const char *) and data()
    (to get at the raw data).
*/

/*! Creates an empty String */

String::String()
    : d( 0 )
{
}

/*! Creates a String from the NUL-terminated string \a s.
    The NUL is not copied. */

String::String( const char *s )
    : d( 0 )
{
    *this = s;
}

/*! Creates a String from the first \a n bytes of \a s, which may
    contain NULs. */

String::String( const char *s, uint n )
    : d( 0 )
{
    append( s, n );
}


/*! Creates a copy of \a s. */

String::String( const String &s )
    : d( 0 )
{
    *this = s;
}


/*! \fn void String::detach()

    Ensures that the string is modifiable. All String functions call
    this prior to modifying the string. */


/*! Destroys the string.

    Because String is used so much, and can eat up such vast amounts
    of memory so quickly, this destructor does something: If the
    string is the sole owner of its data, it frees them.

    As of April 2005, the return values of data() or cstr() are NO
    LONGER valid after a string has gone out of scope or otherwise been
    lost.
*/

String::~String()
{
    if ( modifiable() ) {
        Allocator::dealloc( d->str );
        Allocator::dealloc( d );
    }
    d = 0;
}


/*! Deletes \a p. (This function exists only so that gcc -O3 doesn't
    decide that String objects don't need destruction.)
*/

void String::operator delete( void *p )
{
    if ( ((String *)p)->modifiable() ) {
        Allocator::dealloc( ((String *)p)->d->str );
        Allocator::dealloc( ((String *)p)->d );
    }
    ((String *)p)->d = 0;
}


/*! Copies \a other to this string and returns a reference to this
    string. */

String & String::operator=( const String & other )
{
    d = other.d;
    if ( d )
        d->max = 0;
    return *this;
}


/*! Copies \a s to this string and returns a reference to this
    string. If \a s is a null pointer, the result is an empty string. */

String & String::operator=( const char * s )
{
    if ( !s || !*s ) {
        d = 0;
        return *this;
    }

    uint len = strlen( s );
    if ( d && d->max )
        d->len = 0;
    reserve( len );
    d->len = len;
    memmove( d->str, s, d->len );
    return *this;
}


/*! \fn uint String::length() const

    Returns the length of the string. The length does not include any
    terminator or padding. */


/*! \fn const char *String::data() const

    Returns a pointer to the string's byte representation, which is
    NOT necessarily zero-terminated. */


/*! Returns the zero-terminated byte representation of the
    string. Note that even though the return value is zero-terminated,
    it can also contain null bytes in the middle.

    Even though this function modifies memory, it doesn't detach(),
    since it doesn't modify the string. However, in most cases its
    call to reserve() causes a detach().
*/

const char *String::cstr()
{
    reserve( length()+1 );
    d->str[d->len] = '\0';
    return data();
}


/*! Returns a copy of this string where all upper-case letters (A-Z -
    this is ASCII only) have been changed to lower case. */

String String::lower() const
{
    String result( *this );
    uint i = 0;
    while ( i < result.length() ) {
        if ( result[i] >= 'A' && result[i] <= 'Z' ) {
            result.detach();
            result.d->str[i] = result.d->str[i] + 32;
        }
        i++;
    }
    return result;
}


/*! Returns a copy of this string where all lower-case letters (a-z -
    this is ASCII only) have been changed to upper case. */

String String::upper() const
{
    String result( *this );
    uint i = 0;
    while ( i < result.length() ) {
        if ( result[i] >= 'a' && result[i] <= 'z' ) {
            result.detach();
            result.d->str[i] = result.d->str[i] - 32;
        }
        i++;
    }
    return result;
}


/*! Returns a copy of this string where all letters have been changed
  to conform to typical mail header practice: Letters following digits
  and other letters are lower-cased. Other letters are upper-cased
  (notably including the very first character). */

String String::headerCased() const
{
    String result( *this );
    uint i = 0;
    bool u = true;
    while ( i < length() ) {
        if ( u && result[i] >= 'a' && result[i] <= 'z' ) {
            result.detach();
            result.d->str[i] = result[i] - 32;
        }
        else if ( !u && result[i] >= 'A' && result[i] <= 'Z' ) {
            result.detach();
            result.d->str[i] = result[i] + 32;
        }
        if ( ( result[i] >= 'A' && result[i] <= 'Z' ) ||
             ( result[i] >= 'a' && result[i] <= 'z' ) ||
             ( result[i] >= '0' && result[i] <= '9' ) )
            u = false;
        else
            u = true;
        i++;
    }
    return result;
}





/*! Returns the position of the first occurence of \a c on or after \a i
    in this string, or -1 if there is none.
*/

int String::find( char c, int i ) const
{
    while ( i < (int)length() && at( i ) != c )
        i++;
    if ( i < (int)length() )
        return i;
    return -1;
}


/*! Returns the position of the first occurence of \a s on or after \a i
    in this string, or -1 if there is none.
*/

int String::find( const String & s, int i ) const
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


/*! Appends \a other to this string. */

void String::append( const String & other )
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
    memmove( d->str+d->len, other.d->str, other.d->len );
    d->len += other.d->len;
}


/*! \overload
    This version of append() appends \a num raw bytes from memory
    \a base. If \a base is null, this function does nothing.
*/

void String::append( const char * base, uint num )
{
    if ( !base || !num )
        return;

    reserve( length() + num );
    memmove( d->str + d->len, base, num );
    d->len += num;
}


/*! \overload

    This version of append() appends the null-terminated string \a s,
    or does nothing if \a s is null.
*/

void String::append( const char * s )
{
    if ( s )
        append( s, strlen( s ) );
}


/*! \overload
    This version of append() appends the single character \a c. */

void String::append( char c )
{
    reserve( length() + 1 );
    d->str[d->len] = c;
    d->len++;
}

void String::appendNumber( int n, int base )
{
    if ( n < 0 ) {
        append( '-' );
        n = -n;
    }
    appendNumber( (uint)n, base );
}

void String::appendNumber( uint n, int base )
{
    String s( fromNumber( n, base ) );

    if ( n > 0 )
        append( s );
    else
        append( "0" );
}

/*! Ensures that there is at least \a num bytes available in this
    string. This implicitly causes the string to become modifiable and
    have a nonzero number of available bytes. */

void String::reserve( uint num )
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

void String::reserve2( uint num )
{
    num = Allocator::rounded( num );

    if ( !d ) {
        // empty string: give it a d and be done
        d = new StringData( num );
    }
    else if ( d->max ) {
        // we owned the old string: modify d
        char * s = (char*)Allocator::alloc( num, 0 );
        if ( d->len )
            memmove( s, d->str, d->len );
        d->str = s;
        d->max = num;
    }
    else {
        // the old was shared: detach and use
        StringData * nd = new StringData( num );
        nd->len = d->len;
        if ( nd->len > num )
            nd->len = num;
        if ( d->len )
            memmove( nd->str, d->str, nd->len );
        d = nd;
    }
}


/*! Ensures that the string's length is either \a l or length(),
    whichever is smaller. I \a l is 0 (the default), the string will be
    empty after the function is called.
*/

void String::truncate( uint l )
{
    if ( l < length() ) {
        detach();
        d->len = l;
    }
}


/*! Returns a string containing the data starting at position \a start
    of this string, extending for \a num bytes. \a num may be left out,
    in which case the rest of the string is returned.

    If \a start is too large, an empty string is returned.
*/

String String::mid( uint start, uint num ) const
{
    if ( !d )
        num = 0;
    else if ( num > d->len || start + num > d->len )
        num = d->len - start;

    String result;
    if ( !num || start >= length() )
        return result;

    d->max = 0;
    result.d = new StringData;
    result.d->str = d->str + start;
    result.d->len = num;
    return result;
}


/*! Returns true is the string is quoted with \a c (default '"') as
    quote character and \a q (default '\') as escape character. \a c
    and \a q may be the same. */

bool String::isQuoted( char c, char q ) const
{
    if ( length() < 2 || at( 0 ) != c || at( length() - 1 ) != c )
        return false;
    // skip past double escapes
    uint i = length() - 2;
    while ( i > 1 && d->str[i] == q && d->str[i-1] == q )
        i = i - 2;
    // empty string left?
    if ( i == 0 )
        return true;
    // trailing quote escaped?
    if ( d->str[i] == q )
        return false;
    return true;
}


/*! Returns the unquoted representation of the string if it isQuoted()
    and the string itself else.

    \a c at the start and end are removed; any occurence of \a c
    within the string is left alone; an occurence of \a q followed by
    \a c is converted into just \a c.
*/

String String::unquoted( char c, char q ) const
{
    if ( !isQuoted( c, q ) )
        return *this;
    String r;
    r.reserve( length() );
    uint i = 1;
    while ( i < length()-1 ) {
        if ( d->str[i] == q )
            i++;
        r.append( d->str[i] );
        i++;
    }
    return r;
}


/*! Returns a version of this string quited with \a c, and where any
    occurences of \a c or \a q are escaped with \a q.
*/

String String::quoted( char c, char q ) const
{
    String r;
    r.reserve( length()+2 );
    r.append( c );
    uint i = 0;
    while ( i < length() ) {
        if ( d->str[i] == c || d->str[i] == q )
            r.append( q );
        r.append( d->str[i] );
        i++;
    }
    r.append( c );
    return r;
}


/*! Returns true if this string is really boring, and false if it's
    empty or contains at least one character that may warrant quoting
    in some context. So far RFC822 atoms, 2822 atoms, IMAP atoms and
    MIME tokens are considered.

    This function considers the intersection of those character
    classes to be the Totally boring subset. If \a b is not its
    default value, it may include other characters.
*/

bool String::boring( Boring b ) const
{
    if ( isEmpty() )
        return false; // empty strings aren't boring - they may need quoting
    uint i = 0;
    char c = d->str[i];
    while ( i < length() &&
            ( ( c >= 'a' && c <= 'z' ) ||
              ( c >= 'A' && c <= 'Z' ) ||
              ( c >= '0' && c <= '9' ) ||
              ( c == '!' || c == '#' ||
                c == '$' || c == '&' ||
                c == '+' || c == '-' ) ||
              // XXX: The MIME case is probably 100% untested
              ( b == MIME &&
                ( c == '.' ))))
    {
        i++;
        c = d->str[i];
    }
    if ( i < length() )
        return false; // strings with strange characters aren't boring

    return true; // strings with only the usual suspects are
}


/*! Returns a copy of this string where each run of whitespace is
    compressed to a single ASCII 32, and where leading and trailing
    whitespace is removed altogether.
*/

String String::simplified() const
{
    // scan for the first nonwhitespace character
    uint i = 0;
    uint first = 0;
    while ( i < length() && first == i ) {
        char c = d->str[i];
        if ( c == 9 || c == 10 || c == 13 || c == 32 )
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
        char c = d->str[i];
        if ( c == 9 || c == 10 || c == 13 || c == 32 ) {
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

    String result;
    result.reserve( length() );
    i = 0;
    spaces = 0;
    while ( i < length() ) {
        char c = d->str[i];
        if ( c == 9 || c == 10 || c == 13 || c == 32 ) {
            spaces++;
        }
        else {
            if ( spaces && !result.isEmpty() )
                result.append( ' ' );
            spaces = 0;
            result.append( c );
        }
        i++;
    }
    return result;
}

/*! Returns a copy of this string where leading and trailing spaces
    and tabs have been removed.

    Despite its name, this function does NOT strip white space in
    general. Any internal white space is copied verbatim. CR and LF
    are not treated as white space.
*/

String String::stripWSP() const
{
    if ( length() == 0 ) {
        String r;
        return r;
    }

    uint i = 0;
    while ( i < d->len && ( d->str[i] == '\t' || d->str[i] == ' ' ) )
        i++;

    uint j = d->len - 1;
    while ( j > i && ( d->str[j] == '\t' || d->str[j] == ' ' ) )
        j--;

    if ( i > j ) {
        String r;
        return r;
    }
    return mid( i, j - i + 1 );
}


/*! Returns a copy of this String with at most one trailing LF or CRLF
    removed. If there's more than one LF or CRLF, the remainder are
    left.
*/

String String::stripCRLF() const
{
    uint n = 0;
    if ( endsWith( "\r\n" ) )
        n = 2;
    else if ( endsWith( "\n" ) )
        n = 1;

    return mid( 0, length() - n );
}


/*! Returns the lowercase-hexadecimal representation of the string. */

String String::hex() const
{
    String s;
    s.reserve( length()*2 );

    uint i = 0;
    while ( i < length() ) {
        uint x = d->str[i];
        s.appendNumber( x/16, 16 );
        s.appendNumber( x&15, 16 );
        i++;
    }

    return s;
}

const String operator+( const String & a, const String & b )
{
    String result;
    result.reserve( a.length() + b.length() );
    result.append( a );
    result.append( b );
    return result;
}


/*! Returns true if this string starts with \a prefix, and false if it
    does not.
*/

bool String::startsWith( const String & prefix ) const
{
    return prefix == mid( 0, prefix.length() );
}


/*! Returns true if this string starts with \a prefix, and false if it
    does not.
*/

bool String::startsWith( const char * prefix ) const
{
    if ( !prefix )
        return true;
    uint i = 0;
    while ( prefix[i] && prefix[i] == at( i ) )
        i++;
    if ( prefix[i] )
        return false;
    return true;
}


/*! Returns true if this string ends with \a suffix, and false if it
    does not.
*/

bool String::endsWith( const String & suffix ) const
{
    return suffix == mid( length()-suffix.length() );
}


/*! Returns true if this string ends with \a suffix, and false if it
    does not.
*/

bool String::endsWith( const char * suffix ) const
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


/*! Returns the number encoded by this string, and sets \a *ok to true
    if that number is valid, or to false if the number is invalid. By
    default the number is encoded in base 10, if \a base is specified
    that base is used. \a base must be at least 2 and at most 36.

    If the number is invalid (e.g. negative), the return value is undefined.

    If \a ok is a null pointer, it is not modified.
*/

uint String::number( bool * ok, uint base ) const
{
    uint i = 0;
    uint n = 0;

    bool good = !isEmpty();
    while ( good && i < length() ) {
        if ( d->str[i] < '0' || d->str[i] > 'z' )
            good = false;

        uint digit = d->str[i] - '0';

        // hex or something?
        if ( digit > 9 ) {
            uint c = d->str[i];
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


/*! Returns a string representing the number \a n in the \a base
    system, which is 10 (decimal) by default and must be in the range
    2-36.

    For 0, "0" is returned.

    For bases 11-36, lower-case letters are used for the digits beyond
    9.
*/

String String::fromNumber( uint n, uint base )
{
    if ( !n )
        return "0";

    String s;
    uint i = 0;
    while ( n ) {
        uint d = n%base;
        char  c = '0' + d;
        if ( d > 9 )
            c = 'a' + d - 10;
        s.append( c );
        n = n / base;
    }
    String result;
    result.reserve( s.length() );
    result.d->len = s.d->len;
    i = 0;
    while ( i < s.length() ) {
        result.d->str[s.length()-i-1] = s[i];
        i++;
    }
    return result;
}


/*! Returns an \a e encoded version of this String. If \a e is Base64,
    then \a n specifies the maximum line length.
    The default is 0, i.e. no limit.
*/

String String::encode( Encoding e, uint n ) const
{
    if ( e == Base64 )
        return e64( n );
    else if ( e == QP )
        return eQP();
    return *this;
}


/*! Returns a \a e decoded version of this String. */

String String::decode( Encoding e ) const
{
    if ( e == Base64 )
        return de64();
    else if ( e == QP )
        return deQP();
    return *this;
}


/*! Returns a version of this String with absolutely nothing changed.
    (This function is eventually intended to percent-escape URIs, the
    opposite of deURI().)
*/

String String::eURI() const
{
    return *this;
}


/*! Returns a version of this String with every %xx escape replaced with
    the corresponding character (as used to encode URIs). Invalid escape
    sequences are left unchanged.
*/

String String::deURI() const
{
    uint l = length();

    String s;
    s.reserve( l );

    uint p = 0;
    while ( p < l ) {
        char c = d->str[p];
        if ( c == '%' ) {
            bool ok;
            uint n = mid( p+1, 2 ).number( &ok, 16 );
            if ( ok ) {
                p += 2;
                c = (char)n;
            }
        }
        s.append( c );
        p++;
    }

    return s;
}


static char from64[128] =
{
    64, 99, 99, 99,  99, 99, 99, 99,
    65, 99, 65, 99,  99, 65, 99, 99,
    99, 99, 99, 99,  99, 99, 99, 99,
    99, 99, 99, 99,  99, 99, 99, 99,

        // 32
    99, 99, 99, 99,  99, 99, 99, 99,
    99, 99, 99, 62,  99, 99, 99, 63,
    52, 53, 54, 55,  56, 57, 58, 59,
    60, 61, 99, 99,  99, 64, 99, 99,

        // 64
    99,  0,  1,  2,   3,  4,  5,  6,
     7,  8,  9, 10,  11, 12, 13, 14,
    15, 16, 17, 18,  19, 20, 21, 22,
    23, 24, 25, 99,  99, 99, 99, 99,

        // 96
    99, 26, 27, 28,  29, 30, 31, 32,
    33, 34, 35, 36,  37, 38, 39, 40,
    41, 42, 43, 44,  45, 46, 47, 48,
    49, 50, 51, 99,  99, 99, 99, 99
};



/*! Decodes this string using the base-64 algorithm and returns the result. */

String String::de64() const
{
    // this code comes from mailchen, adapted for String.
    String result;
    result.reserve( length() * 3 / 4 + 20 ); // 20 = fudge
    String body;
    uint bp = 0;
    uint decoded = 0;
    int m = 0;
    uint p = 0;
    bool done = false;
    while ( p < length() && !done ) {
        uint c = d->str[p++];
        if ( c <= 'z' )
            c = from64[c];
        if ( c < 64 ) {
            switch ( m ) {
            case 0:
                decoded = c << 2;
                break;
            case 1:
                decoded += ( (c & 0xf0) >> 4 );
                result.d->str[bp++] = decoded;
                decoded = (c & 15) << 4;
                break;
            case 2:
                decoded += ( (c & 0xfc) >> 2 );
                result.d->str[bp++] = decoded;
                decoded = (c & 3) << 6;
                break;
            case 3:
                decoded += c;
                result.d->str[bp++] = decoded;
                break;
            }
            m = (m+1)&3;
        }
        else if ( c == 64 ) {
            done = true;
        }
        else if ( c == 65 ) {
            // white space; perfectly normal and may be ignored.
        }
        else {
            // we're supposed to ignore all other characters. so
            // that's what we do, even though it may not be ideal in
            // all cases... consider that later.
        }
    }
    result.d->len = bp;
    return result;
}


static char to64[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*! Encodes this string using the base-64 algorithm and returns the
    result in lines of at most \a lineLength characters. If \a
    lineLength is not supplied, e64() returns a single line devoid of
    whitespace.
*/

String String::e64( uint lineLength ) const
{
    // this code comes from mailchen, adapted for String
    int l = length();
    int i = 0;
    String r;
    r.reserve( l*2 );
    int p = 0;
    uint c = 0;
    while ( i <= l-3 ) {
        r.d->str[p++] = to64[ ((d->str[i]>>2))&63 ];
        r.d->str[p++] = to64[ ((d->str[i]<<4)&48) + ((d->str[i+1]>>4)&15) ];
        r.d->str[p++] = to64[ ((d->str[i+1]<<2)&60) + ((d->str[i+2]>>6)&3) ];
        r.d->str[p++] = to64[ (d->str[i+2]&63) ];
        i += 3;
        c += 4;
        if ( lineLength > 0 && c >= lineLength ) {
            r.d->str[p++] = 13;
            r.d->str[p++] = 10;
            c = 0;
        }
    }
    if ( i < l ) {
        int i0, i1, i2;
        i0 = d->str[i];
        i1 = i+1 < l ? d->str[i+1] : 0;
        i2 = i+2 < l ? d->str[i+2] : 0;
        r.d->str[p++] = to64[ ((i0>>2))&63 ];
        r.d->str[p++] = to64[ ((i0<<4)&48) + ((i1>>4)&15) ];
        if ( i+1 < l )
            r.d->str[p++] = to64[ ((i1<<2)&60) + ((i2>>6)&3) ];
        else
            r.d->str[p++] = '=';
        if ( i+2 < l )
            r.d->str[p++] = to64[ (i2&63) ];
        else
            r.d->str[p++] = '=';
    }
    if ( lineLength > 0 && c > 0 ) {
        r.d->str[p++] = 13;
        r.d->str[p++] = 10;
    }
    r.d->len = p;
    return r;
}


/*! Decodes this string according to the quoted-printable algorithm,
    and returns the result. Errors are overlooked, to cope with all
    the mail-munging brokenware in the great big world.

    If \a underscore is true, underscores in the input are translated
    into spaces (as specified in RFC 2047).
*/

String String::deQP( bool underscore ) const
{
    uint i = 0;
    String r;
    r.reserve( length() );
    while ( i < length() ) {
        if ( d->str[i] != '=' ) {
            char c = d->str[i++];
            if ( underscore && c == '_' )
                c = ' ';
            r.d->str[r.d->len++] = c;
        }
        else {
            // are we looking at = followed by end-of-line?
            bool ok = false;
            uint c = 0;
            bool eol = false;
            uint j = i+1;
            // skip possibly appended whitespace first
            while ( j < length() &&
                    ( d->str[j] == ' ' || d->str[j] == '\t' ) )
                j++;
            // there are two types of soft EOLs:
            if ( j < d->len && d->str[j] == 10 ) {
                eol = true;
                j++;
            }
            else if ( j < d->len-1 && d->str[j] == 13 && d->str[j+1] == 10 ) {
                eol = true;
                j = j + 2;
            }
            else if ( i + 2 < d->len ) {
                // ... and one common case: a two-digit hex number, not EOL
                c = mid( i+1, 2 ).number( &ok, 16 );
            }

            // write the proper decoded string and increase i.
            if ( eol ) { // ... if it's a soft EOL
                i = j;
            }
            else if ( ok ) { // ... or if it's a two-digit hex number
                r.d->str[r.d->len++] = c;
                i = i + 3;
            }
            else { // ... or if it's an error... we overlook it
                r.d->str[r.d->len++] = d->str[i++];
            }
        }
    }
    return r;
}


static char qphexdigits[17] = "0123456789ABCDEF";


/*! Encodes this string using the quoted-printable algorithm and
    returns the encoded version. In the encoded version, all line
    feeds are CRLF, and soft line feeds are positioned so that the q-p
    looks as good as it can.

    Note that this function is slightly incompatible with RFC 2646: It
    encodes trailing spaces, as suggested in RFC 2045, but RFC 2646
    suggest that if trailing spaces are the only reason to q-p, then
    the message should not be encoded.

    If \a underscore is present and true, this function uses the variant
    of q-p specified by RFC 2047, where a space is encoded as an
    underscore and a few more characters need to be encoded.
*/

String String::eQP( bool underscore ) const
{
    if ( isEmpty() )
        return *this;
    uint i = 0;
    String r;
    // worst case: three bytes, plus soft line feeds every 48 chars
    r.reserve( length()*3 + length()/16 );
    uint c = 0;
    while ( i < d->len ) {
        if ( d->str[i] == 10 ||
             ( i < d->len-1 && d->str[i] == 13 && d->str[i+1] == 10 ) ) {
            // we have a line feed. if the last character on the line
            // was a space, we need to quote that to protect it.
            if ( r.d->len > 0 && r.d->str[r.d->len-1] == ' ' ) {
                r.d->str[r.d->len-1] = '=';
                r.d->str[r.d->len++] = '2';
                r.d->str[r.d->len++] = '0';
            }
            c = 0;
            if ( d->str[i] == 13 )
                r.d->str[r.d->len++] = d->str[i++];
            r.d->str[r.d->len++] = 10;
        }
        else {
            if ( c > 72 ) {
                uint j = 1;
                while ( j < 10 && r.d->str[r.d->len-j] != ' ' )
                    j++;
                if ( j >= 10 )
                    j = 0;
                else
                    j--;
                uint k = 1;
                while ( k <= j ) {
                    r.d->str[r.d->len - k + 3] = r.d->str[r.d->len - k];
                    k++;
                }
                // always CRLF for soft linefeed
                r.d->str[r.d->len++ - j] = '=';
                r.d->str[r.d->len++ - j] = 13;
                r.d->str[r.d->len++ - j] = 10;
                c = j;
            }

            if ( underscore && d->str[i] == ' ' ) {
                r.d->str[r.d->len++] = '_';
                c += 1;
            }
            else if ( underscore &&
                      ! ( ( d->str[i] >= '0' && d->str[i] <= '9' ) ||
                          ( d->str[i] >= 'a' && d->str[i] <= 'z' ) ||
                          ( d->str[i] >= 'A' && d->str[i] <= 'Z' ) ) ) {
                r.d->str[r.d->len++] = '=';
                r.d->str[r.d->len++] = qphexdigits[d->str[i]/16];
                r.d->str[r.d->len++] = qphexdigits[d->str[i]%16];
                c += 3;
            }
            else if ( ( d->str[i] >= ' ' && d->str[i] < 127 &&
                   d->str[i] != '=' ) ||
                 ( d->str[i] == '\t' ) ) {
                r.d->str[r.d->len++] = d->str[i];
                c++;
            }
            else {
                r.d->str[r.d->len++] = '=';
                r.d->str[r.d->len++] = qphexdigits[d->str[i]/16];
                r.d->str[r.d->len++] = qphexdigits[d->str[i]%16];
                c += 3;
            }
        }
        i++;
    }
    return r;
}


/*! This function returns true if the string would need to be encoded
    using quoted-printable. It is a greatly simplified copy of eQP(),
    with the changes made necessary by RFC 2646.
*/

bool String::needsQP() const
{
    uint i = 0;
    uint c = 0;
    while ( i < length() ) {
        if ( d->str[i] == 10 )
             c = 0;
        else if ( c > 78 )
            return true;
        else if ( ( d->str[i] >= ' ' && d->str[i] < 127 ) ||
                  ( d->str[i] == '\t' ) ||
                  ( d->str[i] == 13 && d->str[i+1] == 10 ) )
            c++;
        else
            return true;
        i++;
    }
    return false;

}


/*! Returns -1 if this string is lexicographically before \a other, 0
    if they are the same, and 1 if this string is lexicographically
    after \a other.

    The comparison is case sensitive - just a byte comparison.
*/

int String::compare( const String & other ) const
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


bool String::operator<( const String & other ) const
{
    return compare( other ) < 0;
}


bool String::operator>( const String & other ) const
{
    return compare( other ) > 0;
}


bool String::operator<=( const String & other ) const
{
    return compare( other ) <= 0;
}


bool String::operator>=( const String & other ) const
{
    return compare( other ) >= 0;
}


bool String::operator<( const char * other ) const
{
    if ( !other )
        return false;

    uint l = length();
    uint i = 0;
    while ( i < l && d->str[i] == other[i] && other[i] )
        i++;
    // four cases: we ran out of characters, other did, both did,
    // there's a difference
    if ( i == l && !other[i] )
        return false;
    if ( !other[i] )
        return false;
    if ( i == l )
        return true;
    return d->str[i] < other[i];
}


/*! This function is a debugging aid. It prints the contents of the
    string within single quotes followed by a trailing newline to
    stderr.
*/

void String::print() const
{
    uint i = 0;

    fprintf( stderr, "'" );
    while ( i < length() )
        fprintf( stderr, "%c", d->str[i++] );
    fprintf( stderr, "'\n" );
}


/*! Returns \a n as a string representing that number in a
    human-readable fashion optionally suffixed by K, M og G.

    The number is rounded more or less correctly.
*/

String String::humanNumber( uint n )
{
    if ( n < 1024 )
        return fromNumber( n );

    uint f = 1024;
    char s = 'K';
    if ( n < 1024 * 1024 ) {
        // ok
    }
    else if ( n < 1024 * 1024 * 1024 ) {
        f = 1024 * 1024;
        s = 'M';
    }
    else {
        f = 1024 * 1024 * 1024;
        s = 'G';
    }

    String r;
    // if it's single-digit, we add a decimal point. to avoid
    // wraparound and wrongness for 32-bit cpus and gigabyte sizes, we
    // check a little harder.
    if ( n < f * 10 || f > UINT_MAX/10 ) {
        n += f/20-1;
        r = fromNumber( n/f );
        uint m = (n%f)/(f/10);
        r.append( '.' );
        r.append( '0' + m );
    }
    else {
        n += f/2-1;
        r = fromNumber( n/f );
    }
    r.append( s );
    return r;
}


// all the keywords we know about, found by grepping through message/*.cpp
static const char * keywords[] = {
    "7bit", "8bit", "binary", "bcc", "cc", "comments", "content-description",
    "content-disposition", "content-id", "content-language",
    "content-location", "content-md5", "content-transfer-encoding",
    "content-type", "date", "fri", "from", "in-reply-to", "jan",
    "keywords", "may", "message-id", "mime-version", "mon", "orig-date",
    "received", "references", "reply-to", "resent-bcc", "resent-cc",
    "resent-date", "resent-from", "resent-message-id", "resent-sender",
    "resent-to", "return-path", "sender", "sep", "subject", "to",
    "us-ascii", "adt", "akdt", "akst", "apr", "ast", "attachment",
    "base64", "body", "boundary", "brt", "bst", "bytes", "cadt", "cast",
    "cct", "cdt", "ces", "cest", "cet", "charset", "cst", "cut", "data",
    "dec", "deleted", "digest", "eadt", "east", "edt", "eet", "est",
    "feb", "flag", "fri", "gmt", "grnlnddt", "grnlndst", "hadt", "hast",
    "helo", "hkt", "hst", "html", "id", "idate", "inline", "jan", "jst",
    "kdt", "kst", "lhlo", "lines", "lockuidnext", "mar", "mdt", "message",
    "mest", "mesz", "met", "metdst", "mez", "mezt", "mon", "msd", "msk",
    "mst", "multipart", "name", "ndt", "nov", "nst", "nzdt", "nzst", "oct",
    "part", "plain", "pdt", "pst", "quit", "quoted-printable", "rawbytes",
    "rfc822", "rfc822size", "root", "sast", "sat", "seen", "sep",
    "supplied", "text", "tue", "uid", "us-ascii", "ut", "utc", "value",
    "wadt", "wast", "wed", "wet", "ydt", "yst",
    0
};
    
// helper for String::anonymised()
static inline bool isMungableChar( char c ) {
    if ( ( c >= 'a' && c <= 'z' ) ||
         ( c >= 'A' && c <= 'Z' ) ||
         ( c >= '0' && c <= '9' ) ||
         ( c == '=' ||
           c == '"' ||
           c == ':' ||
           c == '?' ||
           c == '-' ||
           c == '+' ||
           c == '_' ) )
        return true;
    return false;
}


/*! Returns a copy of this string where most/all content has been
    replaced with the letter 'x' or the digit '4', but if the message
    was an RFC822 message, it keeps the same parse tree.

    Specifically, most ASCII words are changed to xxxx, while most/all
    syntax elements are kept.

    This function is very, very slow. That's okay since it's only used
    for sending bug reports to us, and we all know, that's not a common
    case.
*/

String String::anonymised() const
{
    uint b = 0;
    String r;
    while ( b < length() ) {
        uint e = b;
        while ( e < d->len && isMungableChar( d->str[e] ) )
            e++;
        // we have a word.
        bool munge = true;
        if ( e == b )
            munge = false;

        if ( munge && d->str[e-1] == ':' ) // header field names
            munge = false;

        if ( munge ) { // all-digit "words"
            uint i = b;
            while ( i <= e && 
                    ( ( d->str[i] >= '0' && d->str[i] <= '9' ) ||
                      d->str[i] == '+' || d->str[i] == '-' ) )
                i++;
            if ( i > e )
                munge = false;
        }
            
        if ( munge ) { // mime parameters
            uint i = b;
            while ( i <= e && d->str[i] != '"' && d->str[i] != '=' )
                i++;
            if ( i <= e )
                munge = false;
        }

        if ( munge && // boundary lines
             b + 2 <= e &&
             d->str[b] == '-' && d->str[b+1] == '-' ) {
            munge = false;
        }

        if ( munge ) { // any keyword
            String m = mid( b, e-b ).lower();
            uint i = 0;
            while ( keywords[i] && m != keywords[i] )
                i++;
            if ( keywords[i] )
                munge = false;
        }

        if ( munge ) {
            uint i = 0;
            while ( b + i < e ) {
                char c = d->str[b+i];
                if ( c >= '0' && c <= '9' )
                    r.append( '0' + (i%10) );
                else if ( c >= 'a' && c <= 'z' )
                    r.append( 'a' + (i%26) );
                else if ( c >= 'A' && c <= 'Z' )
                    r.append( 'a' + (i%26) );
                else
                    r.append( c );
                i++;
            }
        }
        else {
            r.append( mid( b, e-b ) );
        }
        b = e;

        while ( b < d->len && !isMungableChar( d->str[b] ) ) {
            r.append( d->str[b] );
            b++;
        }
    }

    return r;
}
