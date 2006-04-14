// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "error.h"

#include "file.h"
#include "list.h"

// fprintf
#include <stdio.h>


static SortedList<Error> * errors = 0;


/*! \class Error error.h

  The Error class contains and outputs error messages.

  In udoc, errors are reported by creating an Error object. Later, the
  static function Error::report() will sort the error messages such
  that the most interesting messages are reported first, limit the
  total number of reports, and output it all.
*/


/*! Constructs an Error report for \a file \a line, whose text is \a
    text. The message is reported immediately if \a file is bad (ie.
    File::valid() is false), and later if the file is OK.

    The returned pointer may be discarded.
*/

Error::Error( File * file, uint line, const String & text )
    : f( file ), l( line ), t( text )
{
    if ( !f )
        return;

    if ( !f->valid() ) {
        blather();
    }
    else {
        if ( !errors )
            errors = new SortedList<Error>;
        errors->insert( this );
    }
}


/*! Reports all stored errors. */

void Error::report()
{
    if ( !errors )
        return;

    List<Error>::Iterator it( errors );
    bool first = true;
    while ( it ) {
        it->blather();
        if ( first && errors->count() > 10 )
            fprintf( stderr, "%s:%d: This is the first of %d errors\n",
                     it->f->name().cstr(), it->l, errors->count() );
        first = false;
        ++it;
    }
}


/*! This private helper reports the error on stdout. */

void Error::blather()
{
    fprintf( stderr, "%s:%d: %s\n", f->name().cstr(), l, t.cstr() );
}


bool Error::operator<=( const Error & other ) const
{
    // if it's the same file, the line number decides
    if ( f == other.f )
        return l <= other.l;
    // if the file is newer, we're <=
    if ( f->modificationTime() >= other.f->modificationTime() )
        return true;
    return false;
}
