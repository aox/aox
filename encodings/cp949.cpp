// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cp949.h"

#include "ustring.h"


static const uint toU[65536] = {
#include "cp949.inc"
};

static const uint toE[65536] = {
#include "cp949-rev.inc"
};


/*! \class Cp949Codec cp949.h

    This class implements a translator between Unicode and the CP949
    character set, which is a superset of the KS C 5601-1992 Korean
    character set, EucKrCodec.

    http://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP949.TXT
    http://www.microsoft.com/globaldev/reference/dbcs/949.mspx

    XXX: It is not yet clear how this charset is used in email.
    "CP949" is not defined in the IANA charset registry, and it seems
    that some programs use "ks_c_5601" and "kc_c_5601-1987" to mean
    CP949 instead of EUC-KR.

    http://lists.w3.org/Archives/Public/ietf-charsets/2001AprJun/0030.html
    http://lists.w3.org/Archives/Public/ietf-charsets/2001AprJun/0033.html
*/

/*! Creates a new Cp949Codec object which pretends its name is \a
    n. The default, null, means "ks_c_5601-1987". */

Cp949Codec::Cp949Codec( const char * n )
    : Codec( n ? n : "KS_C_5601-1987" )
{
}


/*! Returns the encoded representation of the UString \a u. */

String Cp949Codec::fromUnicode( const UString &u )
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

UString Cp949Codec::toUnicode( const String &s )
{
    UString u;

    uint n = 0;
    while ( n < s.length() ) {
        char c = s[n];
        char d = s[n+1];

        if ( c < 128 ) {
            u.append( c );
        }
        else if ( c >= 0x81 && c <= 0xFE &&
                  d >= 0x41 && d <= 0xFE ) {
            uint p = (c << 8) | d;
            if ( toU[p] == 0xFFFD )
                recordError( n, p );
            if ( toU[p] != 0xFFFD || d >= 0x81 )
                n++;
            u.append( toU[p] );
        }
        else {
            recordError( n );
            u.append( 0xFFFD );
        }
        n++;
    }

    return u;
}


// for charset.pl:
//codec KS_C_5601-1987 Cp949Codec
