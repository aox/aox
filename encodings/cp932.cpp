// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cp932.h"

#include "ustring.h"


static const uint toU[65536] = {
#include "cp932.inc"
};

static const uint toE[65536] = {
#include "cp932-rev.inc"
};


/*! \class Cp932Codec cp932.h

    This class implements a translator between Unicode and the CP932
    character set, which is a superset of the Shift_JIS encoding of
    the JIS X 0201/0208:1997 character sets.
*/

/*! Creates a new Cp932Codec object. */

Cp932Codec::Cp932Codec()
    : Codec( "CP932" )
{
}


/*! Returns the encoded representation of the UString \a u. */

String Cp932Codec::fromUnicode( const UString &u )
{
    String s;

    uint i = 0;
    while ( i < u.length() ) {
        uint n = u[i];
        if ( n < 128 ) {
            s.append( (char)n );
        }
        else if ( toE[n] != 0 ) {
            n = toE[n];
            if ( n >> 8 != 0 )
                s.append( n >> 8 );
            s.append( n & 0xff );
        }
        else {
            setState( Invalid );
        }
        i++;
    }

    return s;
}


/*! Returns the Unicode representation of the String \a s. */

UString Cp932Codec::toUnicode( const String &s )
{
    UString u;

    uint n = 0;
    while ( n < s.length() ) {
        char c = s[n];

        if ( c < 128 ) {
            u.append( c );
        }
        else {
            char d;

            if ( ( c >= 0x81 && c <= 0x9F ) ||
                 ( c >= 0xE0 && c <= 0xFC ) )
            {
                d = s[++n];
            }
            else {
                d = c;
                c = 0;
            }

            uint p = (c << 8) | d;
            if ( toU[p] != 0xFFFD )
                u.append( toU[p] );
            else
                recordError( n-1, p );
        }

        n++;
    }

    return u;
}

// for charset.pl:
//codec Shift_JIS Cp932Codec
