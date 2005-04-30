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
    Listener< OCServer >::create(
        "ocd", true, Configuration::OcdAddress, Configuration::OcdPort
    );
    Listener< OCAdmin >::create(
        "ocadmin", true, Configuration::OcAdminAddress,
        Configuration::OcAdminPort
    );
    s.execute();
}
