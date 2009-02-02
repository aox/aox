// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "dict.h"

#include "allocator.h"


/*! \class Dict dict.h
  The Dict class provides a simple string-to-object dictionary.

  It is optimized for simplicity, and for extremely fast lookups when
  the number of items can be estimated in advance. Its other
  facilities are somewhat primitive. There is no iterator, for
  example, and no way to remove an object from the dictionary.

  An item can be added with insert(), retrieved with find() or the
  presence of an item can be tested with contains(). That's it.
*/


/*! \fn Dict::Dict()
    Creates an empty dictionary.
*/

/*! \fn T * Dict::find( const EString &s ) const
    Looks for the object identified by \a s in the dictionary, and
    returns a pointer to it (or 0 if no such object was found).
*/

/*! \fn void Dict::insert( const EString &s, T* r )
    Inserts the object \a r into the dictionary, identified by the
    string \a s.
*/

/*! \fn bool Dict::contains( const EString &s ) const
    Returns true if an object identified by \a s exists in the
    dictionary, and false otherwise.
*/

/*! \class UDict dict.h
    A Dict that takes UString keys.
*/

/*! \fn UDict::UDict()
    Creates an empty dictionary.
*/

/*! \fn T * UDict::find( const UString &s ) const
    Looks for the object identified by \a s in the dictionary, and
    returns a pointer to it (or 0 if no such object was found).
*/

/*! \fn void UDict::insert( const UString &s, T* r )
    Inserts the object \a r into the dictionary, identified by the
    UString \a s.
*/

/*! \fn bool UDict::contains( const UString &s ) const
    Returns true if an object identified by \a s exists in the
    dictionary, and false otherwise.
*/
