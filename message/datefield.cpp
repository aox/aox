// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "datefield.h"

#include "ustring.h"
#include "codec.h"


/*! \class DateField datefield.h
    Represents a single Date field (inherits from HeaderField).

    This simple class encapsulates a Date object in a HeaderField. Its
    only responsiblity is to parse the field and set the field value,
    and it can return the date() so created.
*/


DateField::DateField( HeaderField::Type t )
    : HeaderField( t )
{
}


void DateField::parse( const EString &s )
{
    ::Date d;
    d.setRfc822( s );
    AsciiCodec a;
    setValue( a.toUnicode( d.rfc822() ) );
    if ( !date()->valid() )
        setError( "Could not parse " + s.quoted() );
}


/*! Returns a pointer to the Date object contained by this field. */

::Date * DateField::date() const
{
    ::Date * r = new ::Date;
    r->setRfc822( value().ascii() );
    return r;
}
