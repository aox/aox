// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "eucjp.h"

#include "ustring.h"


static const uint toU[94][94] = {
#include "eucjp.inc"
};

static const uint toE[65536] = {
#include "eucjp-rev.inc"
};


/*! \class EucJpCodec eucjp.h

    This class implements a translator between Unicode and the JIS X
    0208:1990 character set using the EUC-JP encoding.
*/

/*! Creates a new EucJpCodec object. */

EucJpCodec::EucJpCodec()
    : Codec( "EUC-JP" )
{
}


/*! Returns the EUC-JP-encoded representation of the UString \a u. */

String EucJpCodec::fromUnicode( const UString &u )
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

UString EucJpCodec::toUnicode( const String &s )
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
                recordError( n );
            if ( toU[i][j] == 0 || toU[i][j] == 0xFFFD )
                recordError( n, i * 94 + j );
            else
                u.append( toU[i][j] );

            n += 2;
        }

    }

    return u;
}

// for charset.pl:
//codec EUC-JP EucJpCodec
