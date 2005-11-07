// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "gbk.h"

#include "ustring.h"


/*! \class GbkCodec gbk.h
    This class implements a translator between Unicode and GBK (in
    the EUC-CN encoding).
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
        else {
            setState( Invalid );
        }

        n++;
    }

    return u;
}
