#include "test.h"
#include "arena.h"
#include "scope.h"
#include "listener.h"
#include "loop.h"
#include "global.h"
#include "imap.h"
#include "cccp.h"
#include "log.h"
#include "configuration.h"


int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::makeGlobal( ".imapdrc" );

    Log l;
    global.setLog( &l );

    log( "IMAP server started" );
    log( Test::report() );

    // should we pick this up from the config file?
    Listener<IMAP>::create( "IMAP", "", 2052 );
    Listener<CCCP>::create( "CCCP", "", 2053 );

    Configuration::global()->report();

    Loop::start();
}
