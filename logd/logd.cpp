#include "test.h"
#include "arena.h"
#include "scope.h"
#include "listener.h"
#include "loop.h"
#include "global.h"
#include "logserver.h"
#include "configuration.h"

// fprintf()
#include <stdio.h>

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    // this carefully doesn't log anything.
    Configuration::makeGlobal( ".logdrc" );

    // this essentially has to be the first action. if not, the
    // logging of whatever comes before will die a horrible death.
    Listener<LogServer>::create( "Log Server", "", 2054 );

    // this logs.
    Log::global()->log( Test::report() );
    Configuration::global()->report();

    // and if it caused errors, we should quit. bad stuff. but we must
    // try to log the error, so we soldier on.
    if ( Log::disastersYet() )
        fprintf( stderr, "logd: Severe errors on startup! See log files.\n" );

    Loop::start();
}
