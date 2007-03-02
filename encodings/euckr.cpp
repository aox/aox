// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "euckr.h"

#include "ustring.h"


static const uint toU[94][94] = {
#include "ksc5601.inc"
};

static const uint toE[65536] = {
#include "ksc5601-rev.inc"
};


/*! \class EucKrCodec euckr.h

    This codec translates between Unicode and KS C 5601-1992 (apparently
    also known as KS X 1001:1992), encoded with EUC-KR.
*/

/*! Creates a new EucKrCodec object. */

EucKrCodec::EucKrCodec()
    : Codec( "EUC-KR" )
{
}


/*! Returns the EUC-KR-encoded representation of the UString \a u. */

String EucKrCodec::fromUnicode( const UString &u )
{
    String s;

    uint i = 0;
    while ( i < u.length() ) {
        uint n = u[i];
        if ( n < 128 ) {
            s.append( (char)n );
        }
        else if ( n < 65536 && toE[n] != 0 ) {
            n = toE[n];
            s.append( ( n >> 8 ) | 0x80 );
            s.append( ( n & 0xff ) | 0x80 );
        }
        else {
            setState( Invalid );
        }
        i++;
    }

    return s;
}


/*! Returns the Unicode representation of the String \a s. */

UString EucKrCodec::toUnicode( const String &s )
{
    UString u;

    uint n = 0;
    while ( n < s.length() ) {
        char c = s[n];

        if ( c < 128 ) {
            u.append( c );
            n++;
        }
        else {
            char d = s[n + 1];

            uint i = c-128-32-1;
            uint j = d-128-32-1;

            if ( i > 93 || d < 128 || j > 93 )
                recordError( n, s );
            if ( toU[i][j] == 0xFFFD )
                recordError( n, i * 94 + j );
            else
                u.append( toU[i][j] );

            n += 2;
        }

    }

    return u;
}

// for charset.pl:
//codec EUC-KR EucKrCodec
