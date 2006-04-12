// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "server.h"
#include "listener.h"
#include "database.h"
#include "schema.h"
#include "sieve.h"
#include "tls.h"


/*! \nodoc */


int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "sieved", argc, argv );
    s.setup( Server::Report );

    Listener< Sieve >::create(
        "Sieve", Configuration::toggle( Configuration::UseSieve ),
        Configuration::SieveAddress, Configuration::SievePort,
        false
    );

    Database::setup();

    s.setup( Server::Finish );

    Schema::check( &s );

    TlsServer::setup();
    Sieve::setup();

    s.run();
}
