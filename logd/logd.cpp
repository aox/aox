#include "test.h"
#include "arena.h"
#include "scope.h"
#include "listener.h"
#include "loop.h"
#include "global.h"
#include "logserver.h"
#include "configuration.h"
#include "selflogger.h"


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    // this carefully doesn't log anything.
    Configuration::makeGlobal( ".logdrc" );

    (void)new SelfLogger;
    Log l;
    global.setLog( &l );
    Listener<LogServer>::create( "Log Server", "", 2054 );

    log( Test::report() );
    Configuration::global()->report();

    Loop::start();
}
