// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "updatedb.h"

#include "md5.h"
#include "utf.h"
#include "dict.h"
#include "query.h"
#include "cache.h"
#include "ustring.h"
#include "address.h"
#include "transaction.h"
#include "addresscache.h"

#include <stdio.h>
#include <stdlib.h>


/*! \class UpdateDatabase updatedb.h
    This class handles the "aox update database" command.
*/

UpdateDatabase::UpdateDatabase( StringList * args )
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
