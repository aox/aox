// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "server.h"
#include "logclient.h"
#include "listener.h"
#include "database.h"
#include "schema.h"
#include "flag.h"
#include "pop.h"


/*! \nodoc */


int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "pop3d", argc, argv );
    s.setup( Server::Report );

    Listener< POP >::create(
        "POP3", Configuration::toggle( Configuration::UsePop ),
        Configuration::PopAddress, Configuration::PopPort,
        false
    );

    Database::setup();

    Schema::check( &s );
    Flag::setup();

    s.run();
}
