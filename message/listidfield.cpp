// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "listidfield.h"


/*! \class ListIdField listidfield.h

    This class knows how to parse and represent a List-ID as defined
    in RFC 2919.

    Its main reason to exist is that some people use 8-bit phrases in
    list-id, and we need to drop those without dropping the field as a
    whole.
*/



/*!  Constructs an empty ListIdField. */

ListIdField::ListIdField()
    : HeaderField( Other )
{
}


/*! Unremarkable except that it drops 8-bit data inside \a value. */

void ListIdField::parse( const String & value )
{
    uint i = value.length();
    while ( i > 0 && value[i] < 128 )
        i--;
    if ( value[i] < 128 ) {
        setData( value );
        return;
    }

    uint bad = i;
    while ( value[i] != '<' && i < value.length() )
        i++;
    if ( value[i] == '<' ) {
        setData( value.mid( i ) );
        return;
    }

    setError( "8-bit data at index " + fn( bad ) );
}
