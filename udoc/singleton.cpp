// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "singleton.h"

#include "dict.h"
#include "error.h"
#include "file.h"


static Dict<Singleton> * refs = 0;


/*! \class Singleton singleton.h

    The Singleton class defines a singledton, ie. a word or phrase
    which may only be mentioned once in the documentation. It is used
    to ensure that only one Intro introduces a given Class or other
    Intro.

    If a Singleton is created for a the same name as an already
    existing Singleton, error messages are omitted for both of them.
*/


/*! Constructs a Singleton to \a name, which is located at \a file,
    \a line. */

Singleton::Singleton( File * file, uint line, const String & name )
    : f( file ), l( line )
{
    if ( !refs )
        refs = new Dict<Singleton>;
    Singleton * other = refs->find( name );
    if ( other ) {
        (void)new Error( file, line,
                         name + " also mentioned at " +
                         other->file()->name() + " line " +
                         fn( other->line() ) );
        (void)new Error( other->file(), other->line(),
                         name + " also mentioned at " +
                         file->name() + " line " +
                         fn( line ) );
    }
    else {
        refs->insert( name, this );
    }
}


/*! Returns the File where this Singleton was defined. */

File * Singleton::file() const
{
    return f;
}


/*! Returns the line number where this Singleton was defined. */

uint Singleton::line() const
{
    return l;
}
