#include "test.h"
#include "arena.h"
#include "listener.h"
#include "loop.h"
#include "global.h"
#include "imap.h"
#include "cccp.h"
#include "logger.h"


int main( int, char *[] )
{
    Arena firstArena;
    Arena::push( &firstArena );

    Test::runTests();

    Logger::global()->log( "IMAP server started" );

    Listener<IMAP>::createListener( "IMAP", 2052 );
    Listener<CCCP>::createListener( "CCCP", 2053 );

    Loop::start();
}
