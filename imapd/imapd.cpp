#include "test.h"
#include "arena.h"
#include "listener.h"
#include "loop.h"
#include <global.h>

extern Arena *arena;

int main( int, char *[] )
{
    Arena firstArena;
    Arena::push( &firstArena );

    Test::runTests();

    (void)new Listener(Connection::IMAP, 2052, false);
    (void)new Listener(Connection::CCCP, 2053, false);
    try {
        (void)new Listener(Connection::IMAP, 2052, true);
        (void)new Listener(Connection::CCCP, 2053, true);
    } catch ( Exception e ) {
        // no ipv6 support, we assume. better to check that elsewhere.
    }

    Loop::start();
}
