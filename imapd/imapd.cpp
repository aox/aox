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

    Listener::setup();

    Loop::start();
}
