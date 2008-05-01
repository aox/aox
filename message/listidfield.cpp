// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "listidfield.h"

#include "ustring.h"
#include "codec.h"


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


/*! Unremarkable except that it drops 8-bit data inside \a s. */

void ListIdField::parse( const String & s )
{
    AsciiCodec a;
    setValue( a.toUnicode( s ) );
    if ( a.valid() )
        return;
    int lt = s.find( '<' );
    int gt = s.find( '>' );
    if ( lt >= 0 && gt > lt &&
         !s.mid( gt+1 ).contains( '<' ) ) {
        a.setState( Codec::Valid );
        setValue( a.toUnicode( s.mid( lt, gt+1-lt ) ) );
        if ( a.valid() )
            return;
    }

    setError( "8-bit data: " + a.error() );
}
