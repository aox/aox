#include "arena.h"
#include "scope.h"
#include "test.h"
#include "configuration.h"
#include "logclient.h"
#include "log.h"
#include "pop3.h"
#include "listener.h"
#include "loop.h"

// exit
#include <stdlib.h>


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::setup( "mailstore.conf", "pop3d.conf" );

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    Configuration::report();

    Listener< POP3 >::create( "POP3", "", 2056 );

    if ( Log::disastersYet() )
        exit( -1 );

    Loop::start();
}
