// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "listener.h"
#include "ocserver.h"
#include "ocadmin.h"
#include "logclient.h"
#include "server.h"

#include <stdlib.h>


/*! \nodoc */

int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "ocd", argc, argv );

    s.setup( Server::Report );
    Listener< OCServer >::create( "ocd", "127.0.0.1", 2050 );
    Listener< OCAdmin >::create( "ocadmin", "", 2051 );
    s.setup( Server::Finish );

    s.execute();
}
