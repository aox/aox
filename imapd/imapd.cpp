#include "test.h"
#include "arena.h"
#include "listener.h"
#include "loop.h"

extern Arena *arena;

int main( int, char *[] )
{
    Arena firstArena;
    Arena::push( &firstArena );

    Test::runTests();

    (void)new Listener(Connection::IMAP, 2052);
    (void)new Listener(Connection::CCCP, 2053);

    Loop::start();
}
