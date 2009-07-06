// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "anonymise.h"

#include "file.h"

#include <stdio.h>


static AoxFactory<Anonymise>
f( "anonymise", "", "Anonymise a named mail message.",
   "    Synopsis: aox anonymise filename\n\n"
   "    Reads a mail message from the named file, obscures most or\n"
   "    all content and prints the result on stdout. The output\n"
   "    resembles the original closely enough to be used in a bug\n"
   "    report.\n" );



/*! \class Anonymise anonymise.h
    This class handles the "aox anonymise" command.
*/

Anonymise::Anonymise( EStringList * args )
    : AoxCommand( args )
{
    execute();
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
