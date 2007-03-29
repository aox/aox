// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cp950.h"

#include "ustring.h"


static const uint toU[65536] = {
#include "cp950.inc"
};

static const uint toE[65536] = {
#include "cp950-rev.inc"
};


/*! \class Cp950Codec cp950.h

    This class implements a translator between Unicode and the CP950
    character set, which is a superset of the Big5 character set.
*/

/*! Creates a new Cp950Codec object. */

Cp950Codec::Cp950Codec()
    : Codec( "Big5" )
{
}


/*! Returns the encoded representation of the UString \a u. */

String Cp950Codec::fromUnicode( const UString &u )
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

UString Cp950Codec::toUnicode( const String &s )
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

            if ( c >= 0x81 && c <= 0xFE ) {
                d = s[++n];
            }
            else {
                d = c;
                c = 0;
            }

            uint p = (c << 8) | d;
            if ( toU[p] == 0xFFFD )
                recordError( n-1, p );
            u.append( toU[p] );
        }

        n++;
    }

    return u;
}

// for charset.pl:
//codec Big5 Cp950Codec
