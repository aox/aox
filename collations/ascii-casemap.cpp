// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "ascii-casemap.h"


/*! \class AsciiCasemap ascii-casemap.h
    Implements the "i;ascii-casemap" collation from RFC 4790.

    The "i;ascii-casemap" collation is a simple collation that operates
    on octet strings and treats US-ASCII letters case-insensitively. It
    provides equality, substring, and ordering operations. All input is
    valid. Note that letters outside ASCII are not treated case-
    insensitively.
*/

AsciiCasemap::AsciiCasemap()
    : Collation()
{
}


/*! Returns true (all input strings are valid). */

bool AsciiCasemap::valid( const UString & ) const
{
    return true;
}


/*! Returns true if \a a is equal to \a b, and false otherwise. */

bool AsciiCasemap::equals( const UString & a, const UString & b ) const
{
    return compare( a, b ) == 0;
}


/*! Returns true if \a b is a substring of \a a, and false otherwise. */

bool AsciiCasemap::contains( const UString & a, const UString & b ) const
{
    uint i = 0;
    uint j = 0;

    while ( j < b.length() && i+j < a.length() ) {
        uint ca = a[i+j];
        uint cb = b[j];

        if ( ca >= 'a' && ca <= 'z' )
            ca = 'A'+(ca-'a');

        if ( cb >= 'a' && cb <= 'z' )
            cb = 'A'+(cb-'a');

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

int AsciiCasemap::compare( const UString & a, const UString & b ) const
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

            if ( ca >= 'a' && ca <= 'z' )
                ca = 'A'+(ca-'a');

            if ( cb >= 'a' && cb <= 'z' )
                cb = 'A'+(cb-'a');

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
