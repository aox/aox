#include "arena.h"
#include "scope.h"
#include "test.h"
#include "configuration.h"
#include "listener.h"
#include "ocserver.h"
#include "ocadmin.h"
#include "logclient.h"

#include <stdlib.h>


/*! \nodoc */

int main()
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::makeGlobal( ".ocdrc" );

    Log l;
    global.setLog( &l );
    LogClient::setup();

    Listener< OCServer >::create( "Cluster coordination", "", 2050 );
    Listener< OCAdmin >::create( "Cluster administration", "", 2051 );

    log( Test::report() );
    Configuration::global()->report();
    l.commit();

    if ( Log::disastersYet() )
        exit( 1 );

    Loop::start();
}
