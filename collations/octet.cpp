// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "octet.h"


/*! \class Octet octet.h
    Implements the "i;octet" collation from RFC 4790.

    The "i;octet" collation is a simple and fast collation intended for
    use on binary octet strings rather than on character data. Protocols
    that want to make this collation available have to do so by
    explicitly allowing it. If not explicitly allowed, it MUST NOT be
    used. It never returns an "undefined" result. It provides equality,
    substring, and ordering operations.
*/

Octet::Octet()
    : Collation()
{
}


/*! Returns true (all input strings are valid). */

bool Octet::valid( const UString & ) const
{
    return true;
}


/*! Returns true if \a a is equal to \a b, and false otherwise. */

bool Octet::equals( const UString & a, const UString & b ) const
{
    return compare( a, b ) == 0;
}


/*! Returns true if \a b is a substring of \a a, and false otherwise. */

bool Octet::contains( const UString & a, const UString & b ) const
{
    uint i = 0;
    uint j = 0;

    while ( j < b.length() && i+j < a.length() ) {
        uint ca = a[i+j];
        uint cb = b[j];

        if ( ca == cb ) {
            j++;
        }
        else {
            j = 0;
            i++;
        }
    }

    if ( j == b.length() )
        return true;
    return false;
}


/*! Returns -1, 0, or 1 if \a a is smaller than, equal to, or greater
    than \a b, respectively.
*/

int Octet::compare( const UString & a, const UString & b ) const
{
    uint na = a.length();
    uint nb = b.length();

    uint i = 0;
    while ( 1 ) {
        if ( na == 0 && nb == 0 )
            return 0;
        else if ( na == 0 )
            return -1;
        else if ( nb == 0 )
            return 1;

        if ( a[i] != b[i] ) {
            uint ca = a[i];
            uint cb = b[i];

            if ( ca < cb )
                return -1;
            else if ( cb < ca )
                return 1;
        }

        na--;
        nb--;
        i++;
    }
}
