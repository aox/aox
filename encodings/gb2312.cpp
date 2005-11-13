// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "gb2312.h"

#include "ustring.h"


static const uint gbToUnicode[94][94] = {
#include "gb2312.inc"
};

static const uint unicodeToGb[65536] = {
#include "gb2312-rev.inc"
};


/*! \class Gb2312Codec gb2312.h
    This class implements a translator between Unicode and GB2312 (in
    the EUC-CN encoding).
*/

/*! Creates a new GB2312 Codec object. */

Gb2312Codec::Gb2312Codec()
    : Codec( "GB2312" )
{
}


/*! Returns the GB2312-encoded representation of the UString \a u. */

String Gb2312Codec::fromUnicode( const UString &u )
{
    String s;

    uint i = 0;
    while ( i < u.length() ) {
        uint n = u[i];
        if ( n < 128 ) {
            s.append( (char)n );
        }
        else if ( unicodeToGb[n] != 0 ) {
            n = unicodeToGb[n];
            s.append( ( n >> 8 ) );
            s.append( ( n & 0xff ) );
        }
        else {
            setState( Invalid );
        }
        i++;
    }

    return s;
}


/*! Returns the Unicode representation of the String \a s. */

UString Gb2312Codec::toUnicode( const String &s )
{
    UString u;

    uint n = 0;
    while ( n < s.length() ) {
        char c = s[n];

        if ( c < 128 ) {
            u.append( c );
        }
        else {
            char d = s[++n];

            uint i = c-128-32-1;
            uint j = d-128-32-1;

            if ( i > 93 || d < 128 || j > 93 || gbToUnicode[i][j] == 0 )
                setState( Invalid );
            else
                u.append( gbToUnicode[i][j] );
        }

        n++;
    }

    return u;
}

// for charset.pl:
//codec GB2312 Gb2312Codec
