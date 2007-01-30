// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "datefield.h"


/*! \class DateField datefield.h
    Represents a single Date field (inherits from HeaderField).

    This simple class encapsulates a Date object in a HeaderField. Its
    only responsiblity is to parse the field and set the field value,
    and it can return the date() so created.
*/


DateField::DateField( HeaderField::Type t )
    : HeaderField( t ),
      d( 0 )
{
}


void DateField::parse( const String &s )
{
    d = new ::Date;
    d->setRfc822( s );
    setData( d->rfc822() );
    if ( !date()->valid() )
        setError( "Could not parse " + s.quoted() );
}


/*! Returns a pointer to the Date object contained by this field. */

::Date *DateField::date() const
{
    if ( d )
        return d;

    // d is mutable, constructed on demand, so since we don't use the
    // mutable keyword, let's override the const.
    ((DateField*)this)->d = new ::Date;
    ((DateField*)this)->d->setRfc822( data() );
    return ((DateField*)this)->d;
}
