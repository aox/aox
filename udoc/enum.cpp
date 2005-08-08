// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "enum.h"


/*! \class Enum enum.h

    The Enum class models enums as part of top-level classes. An enum,
    as far as this class knows, simply is a documentable list of
    identifiers, each of which may also be documented.

    The value of each enum member is not kept, as that is an
    implementation matter rather than an interface matter. Further,
    when two enum members are equal, they are treated as separate by
    this class.
*/


/*! Constructs an Enum named \a n in \a c, whose source definition is
    in file \a f line \a l.
*/

Enum::Enum( Class * c, const String & n, File * f, uint l )
    : Garbage()
{
    this->c = c; // ick. I must be drunk to do such a thing.
    this->n = n;
    this->f = f;
    this->l = l;
}


/*! Records that \a name is a member of this enum. */

void Enum::addValue( const String & name )
{
    v.append( name );
}


/*! Returns a pointer to the list of values for this Enum.

*/

StringList * Enum::values() const
{
    return 0;
}
