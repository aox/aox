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

    Configuration::setup( "mailstore.conf", "ocd.conf" );

    Loop::setup();

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    log( Test::report() );

    Listener< OCServer >::create( "Cluster coordination", "", 2050 );
    Listener< OCAdmin >::create( "Cluster administration", "", 2051 );

    Configuration::report();
    l.commit();

    if ( Log::disastersYet() )
        exit( 1 );

    Loop::start();
}
