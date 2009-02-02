// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "anonymise.h"

#include "file.h"

#include <stdio.h>


/*! \class Anonymise anonymise.h
    This class handles the "aox anonymise" command.
*/

Anonymise::Anonymise( EStringList * args )
    : AoxCommand( args )
{
}


void Anonymise::execute()
{
    EString s( next() );
    end();

    File f( s );
    if ( f.valid() )
        fprintf( stdout, "%s\n", f.contents().anonymised().cstr() );
    else
        error( "Couldn't open file: " + s );

    finish();
}
