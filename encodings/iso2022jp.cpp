// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "iso2022jp.h"

#include "ustring.h"


static const uint toU[94][94] = {
#include "jisx0208.inc"
};

static const uint toE[65536] = {
#include "jisx0208-rev.inc"
};


/*! \class Iso2022JpCodec iso2022jp.h

    This class implements a translator between Unicode and the JIS X
    0208:1990 character set using the ISO-2022-JP encoding.

    This class has some relation to RFC 1468. Crab, could you elaborate?
*/

/*! Creates a new Iso2022JpCodec object. */

Iso2022JpCodec::Iso2022JpCodec()
    : Codec( "ISO-2022-JP" )
{
}


/*! Returns the ISO-2022-JP-encoded representation of the UString \a u. */

String Iso2022JpCodec::fromUnicode( const UString &u )
{
    String s;

    enum { ASCII, JIS } mode = ASCII;

    uint i = 0;
    while ( i < u.length() ) {
        uint n = u[i];

        if ( n < 128 ) {
            if ( mode == JIS ) {
                s.append( 0x1B );
                s.append( 0x28 );
                s.append( 0x42 );
                mode = ASCII;
            }
            if ( n == 0x1B || n == 0x0E || n == 0x0F ) {
                recordError( i );
                break;
            }
            s.append( (char)n );
        }
        else if ( n < 65536 && toE[n] != 0 ) {
            if ( mode == ASCII ) {
                s.append( 0x1B );
                s.append( 0x24 );
                s.append( 0x42 );
                mode = JIS;
            }
            n = toE[n];
            s.append( ( n >> 8 ) );
            s.append( ( n & 0xff ) );
        }
        else {
            recordError( i );
        }
        i++;
    }

    if ( mode == JIS ) {
        s.append( 0x1B );
        s.append( 0x28 );
        s.append( 0x42 );
    }

    return s;
}


/*! Returns the Unicode representation of the String \a s. */

UString Iso2022JpCodec::toUnicode( const String &s )
{
    UString u;

    enum { ASCII, JIS } mode = ASCII;

    int ku = 0;
    int ten = 0;

    uint n = 0;
    while ( n < s.length() ) {
        char c = s[n];

        if ( c == 0x1b ) {
            ku = ten = 0;
            if ( ( s[n+1] == 0x28 && s[n+2] == 0x42 ) ||
                 ( s[n+1] == 0x28 && s[n+2] == 0x4a ) )
            {
                // We treat JIS X 0201:1976 as ASCII.
                mode = ASCII;
            }
            else if ( ( s[n+1] == 0x24 && s[n+2] == 0x40 ) ||
                      ( s[n+1] == 0x24 && s[n+2] == 0x42 ) )
            {
                // We treat JIS C 6226:1978 and JIS X 0208:1983 the
                // same as JIS X 0208:1990.
                mode = JIS;
            }
            else {
                // We reject any unknown escape sequences.
                recordError( n, s );
                break;
            }
            n += 2;
        }
        else if ( mode == ASCII ) {
            // Bare SI/SO are forbidden. RFC 1468's strictures against
            // CRLF (being an ABNF gimmick) are ignored here.
            if ( c == 0x0E || c == 0x0F ) {
                recordError( n, s );
                break;
            }
            u.append( c );
        }
        else if ( mode == JIS ) {
            if ( ku == 0 ) {
                ku = (int)c;
            }
            else {
                ten = (int)c;

                if ( ku < 33 || ku > 126 ||
                     ten < 33 || ten > 126 )
                    recordError( n, s );

                ku -= 33;
                ten -= 33;

                if ( toU[ku][ten] == 0xFFFD )
                    recordError( n, ku * 94 + ten );
                else
                    u.append( toU[ku][ten] );
                ku = ten = 0;
            }
        }

        n++;
    }

    // I get the feeling this may be one of the first restrictions to be
    // relaxed on the basis of real-world usage.
    if ( mode != ASCII )
        recordError( "ISO-2022-JP sequence didn't end in ASCII at "
                     "index " + fn( n ) );

    return u;
}

// for charset.pl:
//codec ISO-2022-JP Iso2022JpCodec
