// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "gbk.h"

#include "ustring.h"


static const uint gbkToUnicode[65536] = {
#include "gbk.inc"
};

static const uint unicodeToGbk[65536] = {
#include "gbk-rev.inc"
};


/*! \class GbkCodec gbk.h
    This class implements a translator between Unicode and GBK (in
    the EUC-CN encoding). The CP936 data is used for the mapping.
    This should be merged with the GB2312 codec eventually.
*/

/*! Creates a new GBK Codec object. */

GbkCodec::GbkCodec()
    : Codec( "GBK" )
{
}


/*! Returns the GBK-encoded representation of the UString \a u. */

String GbkCodec::fromUnicode( const UString &u )
{
    String s;

    uint i = 0;
    while ( i < u.length() ) {
        uint n = u[i];
        if ( n < 128 ) {
            s.append( (char)n );
        }
        else if ( unicodeToGbk[n] != 0 ) {
            n = unicodeToGbk[n];
            if ( n != 0x80 )
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

UString GbkCodec::toUnicode( const String &s )
{
    UString u;

    uint n = 0;
    while ( n < s.length() ) {
        char c = s[n];

        if ( c < 128 ) {
            u.append( c );
        }
        else if ( c == 0x80 ) {
            u.append( gbkToUnicode[0x80] );
        }
        else {
            char d = s[++n];
            uint p = (c << 8) | d;
            if ( gbkToUnicode[p] != 0 ) {
                u.append( gbkToUnicode[p] );
            }
            else {
                recordError( n-1, p );
                u.append( 0xFFFD );
            }
        }

        n++;
    }

    return u;
}

// for charset.pl:
//codec GBK GbkCodec
