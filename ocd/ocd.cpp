#include "arena.h"
#include "scope.h"
#include "test.h"
#include "configuration.h"
#include "listener.h"
#include "ocserver.h"
#include "ocadmin.h"

#include <stdlib.h>


int main()
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::makeGlobal( ".ocdrc" );

    Log::setup();

    Listener< OCServer >::create( "Cluster coordination", "", 2050 );
    Listener< OCAdmin >::create( "Cluster administration", "", 2051 );

    Log::global()->log( Test::report() );
    Configuration::global()->report();

    if ( Log::disastersYet() )
        exit( 1 );

    Loop::start();
}
