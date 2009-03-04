// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "updatedb.h"

#include "md5.h"
#include "utf.h"
#include "dict.h"
#include "query.h"
#include "ustring.h"
#include "address.h"
#include "transaction.h"

#include <stdio.h>
#include <stdlib.h>


static AoxFactory<UpdateDatabase>
f( "update", "database", "Update the database contents.",
   "    Synopsis: aox update database\n\n"
   "    Performs any updates to the database contents which are too\n"
   "    slow for inclusion in \"aox upgrade schema\". This command is\n"
   "    meant to be used while the server is running. It does its\n"
   "    work in small chunks, so it can be restarted at any time,\n"
   "    and is tolerant of interruptions.\n" );


/*! \class UpdateDatabase updatedb.h
    This class handles the "aox update database" command.
*/

UpdateDatabase::UpdateDatabase( EStringList * args )
    : AoxCommand( args )
{
    d = 0;
}


void UpdateDatabase::execute()
{
    end();
    printf( "No updates are necessary.\n" );
    finish();
}
