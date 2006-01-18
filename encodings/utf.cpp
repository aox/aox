// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "utf.h"

#include "string.h"
#include "ustring.h"


/*! \class Utf8Codec utf.h
    The Utf8Codec class implements the codec described in RFC 2279

    This is also the same as in the Unicode book, but this
    implementation follows RFC 2279.

    Overlong forms (e.g. 0xC0 Ox80 for U+0000) are allowed by the
    decoder, but considered badly formed.
*/

/*! Constructs a simple UTF8 decoder/encoder. */

Utf8Codec::Utf8Codec()
    : Codec( "UTF-8" )
{
}


// from RFC 2279:

// UCS-4 range (hex.)    UTF-8 octet sequence (binary)
// 0000 0000-0000 007F   0xxxxxxx
// 0000 0080-0000 07FF   110xxxxx 10xxxxxx
// 0000 0800-0000 FFFF   1110xxxx 10xxxxxx 10xxxxxx
// 0001 0000-001F FFFF   11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
// 0020 0000-03FF FFFF   111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
// 0400 0000-7FFF FFFF   1111110x 10xxxxxx ... 10xxxxxx



String Utf8Codec::fromUnicode( const UString & u )
{
    String r;
    uint i = 0;
    while ( i < u.length() ) {
        int c = u[i];
        if ( c < 0x80 ) {
            r.append( (char)c );
        }
        else if ( c < 0x800 ) {
            r.append( 0xc0 | ((char)(c >> 6)) );
            r.append( 0x80 | ((char)(c & 0x3f)) );
        }
        else if ( c < 0x10000 ) {
            r.append( 0xe0 | ((char)(c >> 12)) );
            r.append( 0x80 | ((char)(c >> 6) & 0x3f) );
            r.append( 0x80 | ((char)(c & 0x3f)) );
        }
        else if ( c < 0x200000 ) {
            r.append( 0xf0 | ((char)(c >> 18)) );
            r.append( 0x80 | ((char)(c >> 12) & 0x3f) );
            r.append( 0x80 | ((char)(c >> 6) & 0x3f) );
            r.append( 0x80 | ((char)(c & 0x3f)) );
        }
        else if ( c < 0x4000000 ) {
            r.append( 0xf8 | ((char)(c >> 24)) );
            r.append( 0x80 | ((char)(c >> 18) & 0x3f) );
            r.append( 0x80 | ((char)(c >> 12) & 0x3f) );
            r.append( 0x80 | ((char)(c >> 6) & 0x3f) );
            r.append( 0x80 | ((char)(c & 0x3f)) );
        }
        else if ( c > 0 ) {
            r.append( 0xfc | ((char)(c >> 30)) );
            r.append( 0x80 | ((char)(c >> 24) & 0x3f) );
            r.append( 0x80 | ((char)(c >> 18) & 0x3f) );
            r.append( 0x80 | ((char)(c >> 12) & 0x3f) );
            r.append( 0x80 | ((char)(c >> 6) & 0x3f) );
            r.append( 0x80 | ((char)(c & 0x3f)) );
        }
        i++;
    }
    return r;
}


static bool ahead( const String & s, int i, uint l )
{
    int j = i+1;
    while ( l > 0 ) {
        if ( (s[j] & 0xc0) != 0x80 )
            return false;
        j++;
        l--;
    }
    return true;
}


static int pick( const String & s, int i, uint l )
{
    int a = 0;
    while ( l > 0 ) {
        i++;
        a = (a << 6) | (s[i] & 0x3f);
        l--;
    }
    return a;
}

/*! Decodes the UTF-8 string \a s and returns the result. */

UString Utf8Codec::toUnicode( const String & s )
{
    UString u;
    uint i = 0;
    while ( valid() && i < s.length() ) {
        int c = 0;
        if ( s[i] < 0x80 ) {
            // 0000 0000-0000 007F   0xxxxxxx
            c = s[i];
            i += 1;
        }
        else if ( (s[i] & 0xe0) == 0xc0 && ahead( s, i, 1 ) ) {
            // 0000 0080-0000 07FF   110xxxxx 10xxxxxx
            c = ((s[i] & 0x1f) << 6) | pick( s, i, 1 );
            if ( c < 0x80 )
                setState( BadlyFormed );
            i += 2;
        }
        else if ( (s[i] & 0xf0) == 0xe0 && ahead( s, i, 2 ) ) {
            // 0000 0800-0000 FFFF   1110xxxx 10xxxxxx 10xxxxxx
            c = ((s[i] & 0x0f) << 12) | pick( s, i, 2 );
            if ( c < 0x800 )
                setState( BadlyFormed );
            i += 3;
        }
        else if ( (s[i] & 0xf8) == 0xf0 && ahead( s, i, 3 ) ) {
            // 0001 0000-001F FFFF   11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
            c = ((s[i] & 0x07) << 18) | pick( s, i, 3 );
            if ( c < 0x10000 )
                setState( BadlyFormed );
            i += 4;
        }
        else if ( (s[i] & 0xfc) == 0xf8 && ahead( s, i, 4 ) ) {
            // 0020 0000-03FF FFFF   111110xx 10xxxxxx 10xxxxxx ... 10xxxxxx
            c = ((s[i] & 0x03) << 24) | pick( s, i, 4 );
            if ( c < 0x200000 )
                setState( BadlyFormed );
            i += 5;
        }
        else if ( (s[i] & 0xfe) == 0xfc && ahead( s, i, 5 ) ) {
            // 0400 0000-7FFF FFFF   1111110x 10xxxxxx ... 10xxxxxx
            c = ((s[i] & 0x01) << 30) | pick( s, i, 5 );
            if ( c < 0x4000000 )
                setState( BadlyFormed );
            i += 6;
        }
        else {
            recordError( i );
            return u;
        }
        u.append( c );
    }
    return u;
}


//codec UTF-8 Utf8Codec
