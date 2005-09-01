// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "logclient.h"
#include "pop3.h"
#include "listener.h"
#include "database.h"
#include "server.h"
#include "flag.h"
#include "schema.h"


/*! \nodoc */

int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "pop3d", argc, argv );
    s.setup( Server::Report );

    Listener< POP3 >::create(
        "POP3", Configuration::toggle( Configuration::UsePop ),
        Configuration::PopAddress, Configuration::PopPort
    );

    Database::setup();

    Schema::check( &s );
    Flag::setup();

    s.execute();
}
