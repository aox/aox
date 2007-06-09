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
    : Codec( "UTF-8" ), pgutf( false )
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
        if ( pgutf && !c ) {
            // append U+ED00 since postgres cannot store 0 bytes
            r.append( 0xEE );
            r.append( 0xB4 );
            r.append( 0x80 );
        }
        else if ( c < 0x80 ) {
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
    while ( i < s.length() ) {
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
            if ( c == 0xED00 && pgutf )
                c = 0;
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
            recordError( i, s );
            c = 0xFFFD;
            i++;
        }
        u.append( c );
    }
    return u;
}


/*! \class PgUtf8Codec utf.h
    The PgUtf8Codec is a simple modification of Utf8Codec to be able
    to use PostgreSQL 8.1 well.

    PostgreSQL 8.1 refuses to store the unicode codepoint 0. The
    software reports that it is an invalid byte sequence and refers to
    htt://www.postgresql.org/docs/techdocs.50, but the real reason is
    that postgresql never was intended to store nulls in text, and
    versions up to 8.0 allowed it only by accident.

    Since quite a few messages contain null bytes, we remap 0 to
    U+ED00 (a private-use codepoint, also used by Unknown8BitCodec)
    and back.

    This class is not listed as a supported codec, since it's meant
    only for postgres use, not for any other purpose.
*/


/*!  Constructs an empty PgUtf8Codec. */

PgUtf8Codec::PgUtf8Codec()
    : Utf8Codec()
{
    pgutf = true;
}




/*! \class Utf16Codec utf.h
    The Utf16Codec implements UTF-16 as specified in RFC 2781.

    For decoding, Utf16Codec autodetects UTF-16BE or -LE based on the
    BOM, and for encoding it uses UTF-16BE with a BOM until/unless
    decoding autodetects UTF-16LE or UTF-16BE without a BOM. In
    practice it always uses UTF-16BE with a BOM.
*/


/*! Constructs a simple UTF-16 encoder/decoder. For decoding, the
    backend is autoselected.
*/

Utf16Codec::Utf16Codec()
    : Codec( "UTF-16" ), be( true ), bom( true )
{
    // nothing
}


String Utf16Codec::fromUnicode( const UString & u )
{
    String r;

    if ( !bom ) {
        // if we don't output a BOM, reader should assume BE, so we
        // must be BE to conform
        be = true;
    }
    else if ( be ) {
        r.append( 0xfe );
        r.append( 0xff );
    }
    else {
        r.append( 0xfe );
        r.append( 0xff );
    }

    if ( be )
        r.append( (new Utf16BeCodec)->fromUnicode( u ) );
    else
        r.append( (new Utf16LeCodec)->fromUnicode( u ) );

    return r;
}


UString Utf16Codec::toUnicode( const String & s )
{
    if ( s[0] == 0xFF && s[1] == 0xFE ) {
        be = false;
        bom = true;
    }
    else if ( s[0] == 0xFE && s[1] == 0xFF ) {
        be = true;
        bom = true;
    }
    else {
        be = true;
        bom = false;
    }

    Codec * c = 0;
    if ( be )
        c = new Utf16BeCodec;
    else
        c = new Utf16LeCodec;
    UString r = c->toUnicode( s );

    setState( c->state() );
    if ( c->state() == Invalid )
        recordError( c->error() );
    return r;
}


/*! \class Utf16LeCodec utf.h
    The Utf16LeCodec implements UTF-16LE as specified in RFC 2781.

    Utf16LeCodec removes a BOM while decoding and does not add one
    while encoding.
*/


/*! Constructs a simple UTF-16LE encoder/decoder.
*/


Utf16LeCodec::Utf16LeCodec()
    : Codec( "UTF-16LE" )
{
    // nothing
}


String Utf16LeCodec::fromUnicode( const UString & u )
{
    String r;
    r.reserve( u.length() * 2 );
    uint i = 0;
    while ( i < u.length() ) {
        r.append( u[i] % 0x100 );
        r.append( u[i] / 0x100 );
        i++;
    }
    return r;
}


/*! toUnicode() is probably a little lax. No. It IS a little lax. We
    may tighten this later. At least, we can check that \a s has an
    even length.
*/

UString Utf16LeCodec::toUnicode( const String & s )
{
    UString u;
    u.reserve( s.length() / 2 );
    uint i = 0;
    while ( i < s.length() ) {
        uint c = s[i] + 0x100 * s[i+1];
        if ( !u.isEmpty() || c != 0xFEFF )
            u.append( c );
        i += 2;
    }
    return u;
}


/*! \class Utf16BeCodec utf.h
    The Utf16BeCodec implements UTF-16BE as specified in RFC 2781.

    Utf16BeCodec removes a BOM while decoding and does not add one
    while encoding.
*/


/*! Constructs a simple UTF-16BE encoder/decoder.
*/


Utf16BeCodec::Utf16BeCodec()
    : Codec( "UTF-16BE" )
{
    // nothing
}


String Utf16BeCodec::fromUnicode( const UString & u )
{
    String r;
    r.reserve( u.length() * 2 );
    uint i = 0;
    while ( i < u.length() ) {
        r.append( u[i] / 0x100 );
        r.append( u[i] % 0x100 );
        i++;
    }
    return r;
}


/*! toUnicode() is probably a little lax. No. It IS a little lax. We
    may tighten this later. At least, we can check that \a s has an
    even length.
*/

UString Utf16BeCodec::toUnicode( const String & s )
{
    UString u;
    u.reserve( s.length() / 2 );
    uint i = 0;
    while ( i < s.length() ) {
        uint c = s[i] * 0x100 + s[i+1];
        if ( !u.isEmpty() || c != 0xFEFF )
            u.append( c );
        i += 2;
    }
    return u;
}


//codec UTF-8 Utf8Codec
//codec UTF-16 Utf16Codec
//codec UTF-16BE Utf16BeCodec
//codec UTF-16LE Utf16LeCodec
