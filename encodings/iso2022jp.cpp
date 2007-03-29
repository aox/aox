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
    0208:1990 character set using the ISO-2022-JP encoding, which is
    described in RFC1468.

    In summary: text starts as ASCII, but can switch to either JIS X
    0201 (the "Roman" character set) or JIS X 0208 through an escape
    sequence; a different escape sequence switches back to ASCII. In
    double-byte JIS X 0208 mode, successive bytes are ku/ten indexes
    (0+33 to 93+33) into an ISO-2022 style 94x94 character grid.
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

    uint n = 0;
    while ( n < s.length() ) {
        char c = s[n];

        if ( c == 0x1b ) {
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
                // We ignore any unknown escape sequences.
                recordError( n, s );
                // XXX: should we emit U+FFFD?
            }
            n += 2;
        }
        else if ( mode == ASCII ) {
            // Bare SI/SO are forbidden. RFC 1468's strictures against
            // CRLF (being an ABNF gimmick) are ignored here.
            if ( c == 0x0E || c == 0x0F ) {
                recordError( n, s );
                u.append( 0xFFFD );
            }
            else {
                u.append( c );
            }
        }
        else if ( mode == JIS ) {
            int ku = c;
            int ten = s[n+1];

            uint cp = 0xFFFD;
            if ( ten == 0x1B ) {
                // Single byte
                recordError( n, s );
            }
            else {
                // Double byte, of whatever legality
                ku -= 33;
                ten -= 33;
                if ( ku > 93 || ten > 93 )
                    recordError( n, s );
                else if ( toU[ku][ten] == 0xFFFD )
                    recordError( n, ku * 94 + ten );
                else
                    cp = toU[ku][ten];
                n++;
            }
            u.append( cp );
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
