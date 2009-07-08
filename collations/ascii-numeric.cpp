// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "ascii-numeric.h"


static uint number( const UString & a )
{
    uint i = 0;
    while ( a[i] == '0' )
        i++;

    uint start = i;
    while ( a[i] >= '0' && a[i] <= '9' )
        i++;

    UString n( a.mid( start, i-start ) );

    if ( n.isEmpty() ) {
        if ( start != 0 )
            return 0;
        else
            return UINT_MAX;
    }
    return n.number( 0 );
}


/*! \class AsciiNumeric ascii-numeric.h
    Implements the "i;ascii-numeric" collation from RFC 4790.

    The "i;ascii-numeric" collation is a simple collation intended for
    use with arbitrarily-sized, unsigned decimal integer numbers stored
    as octet strings. US-ASCII digits (0x30 to 0x39) represent digits of
    the numbers. Before converting from string to integer, the input
    string is truncated at the first non-digit character. All input is
    valid; strings that do not start with a digit represent positive
    infinity.
*/

AsciiNumeric::AsciiNumeric()
    : Collation()
{
}


/*! Returns true (all input strings are valid). */

bool AsciiNumeric::valid( const UString & ) const
{
    return true;
}


/*! Returns true if \a a is equal to \a b, and false otherwise. */

bool AsciiNumeric::equals( const UString & a, const UString & b ) const
{
    if ( number( a ) == number( b ) )
        return true;
    return false;
}


/*! Returns false (this collation doesn't support substring operations).
*/

bool AsciiNumeric::contains( const UString &, const UString & ) const
{
    return false;
}


/*! Returns -1, 0, or 1 if \a a is smaller than, equal to, or greater
    than \a b, respectively.
*/

int AsciiNumeric::compare( const UString & a, const UString & b ) const
{
    uint na = number( a );
    uint nb = number( b );

    if ( na < nb )
        return -1;
    else if ( nb < na )
        return 1;
    return 0;
}
