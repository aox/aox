// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "iso2022kr.h"

#include "ustring.h"


static const uint toU[94][94] = {
#include "ksc5601.inc"
};

static const uint toE[65536] = {
#include "ksc5601-rev.inc"
};


/*! \class Iso2022KrCodec iso2022kr.h

    This class implements a translator between Unicode and the KS C 5601
    1992 character set using the ISO-2022-KR encoding, as described in
    RFC 1557.

    Unlike ISO-2022-JP, this encoding uses a single escape sequence
    to identify the KS C 5601-1992 charset, and then SI/SO to switch
    between that and ASCII. The encoding uses an escape code only to
    identify "lines" that contain SO (i.e. KS C 5601 characters), but
    some documents may include this only once at the beginning.

    Apparently, iso-2022-kr is not used in message headers, where
    EUC-KR is preferred instead.
*/

/*! Creates a new Iso2022KrCodec object. */

Iso2022KrCodec::Iso2022KrCodec()
    : Codec( "ISO-2022-KR" )
{
}


/*! Returns the ISO-2022-KR-encoded representation of the UString
    \a u.
*/

String Iso2022KrCodec::fromUnicode( const UString &u )
{
    String s;

    enum { ASCII, KSC } mode = ASCII;

    // XXX: We don't emit the ESC$)C code properly.

    uint i = 0;
    while ( i < u.length() ) {
        uint n = u[i];

        if ( n < 128 ) {
            if ( mode == KSC ) {
                s.append( 0x0F );
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
                s.append( 0x0E );
                mode = KSC;
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

    return s;
}


/*! Returns the Unicode representation of the String \a s. */

UString Iso2022KrCodec::toUnicode( const String &s )
{
    UString u;

    enum { ASCII, KSC } mode = ASCII;

    uint n = 0;
    while ( n < s.length() ) {
        char c = s[n];

        if ( c == 0x1b ) {
            if ( s[n+1] == '$' && s[n+2] == ')' && s[n+3] == 'C' ) {
                // We don't do anything with this valid escape.
            }
            else {
                // We reject any unknown escape sequences.
                recordError( n, s );
                break;
            }
            n += 2;
        }
        else if ( mode == ASCII ) {
            if ( c == 0x0E ) {
                mode = KSC;
            }
            else if ( c == 0x0F ) {
                recordError( n, s );
                break;
            }
            else {
                u.append( c );
            }
        }
        else if ( mode == KSC ) {
            int ku = c;
            int ten = s[n+1];

            if ( c == 0x0E ) {
                mode = ASCII;
            }
            else if ( ten == 0x1B ) {
                // Single byte
                recordError( n, s );
            }
            else {
                // Double byte, of whatever legality
                uint cp = 0xFFFD;
                ku -= 33;
                ten -= 33;
                if ( ku > 93 || ten > 93 )
                    recordError( n, s );
                else if ( toU[ku][ten] == 0xFFFD )
                    recordError( n, ku * 94 + ten );
                else
                    cp = toU[ku][ten];
                u.append( cp );
                n++;
            }
        }

        n++;
    }

    return u;
}

// for charset.pl:
//codec ISO-2022-KR Iso2022KrCodec
