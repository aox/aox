#include "test.h"
#include "arena.h"
#include "scope.h"
#include "listener.h"
#include "loop.h"
#include "global.h"
#include "logserver.h"
#include "configuration.h"
#include "selflogger.h"


int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    // this carefully doesn't log anything.
    Configuration::makeGlobal( ".logdrc" );

    (void)new SelfLogger;
    Listener<LogServer>::create( "Log Server", "", 2054 );

    Log::global()->log( Test::report() );
    Configuration::global()->report();

    Loop::start();
}
