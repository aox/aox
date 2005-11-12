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
      d( new ::Date )
{
}


void DateField::parse( const String &s )
{
    d->setRfc822( s );
    if ( !d->valid() )
        setError( "Could not parse '" + s.simplified() + "'" );
    setData( d->rfc822() );
}


/*! Returns a pointer to the Date object contained by this field. */

::Date *DateField::date() const
{
    return d;
}
