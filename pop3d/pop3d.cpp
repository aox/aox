#include "arena.h"
#include "scope.h"
#include "logclient.h"
#include "pop3.h"
#include "listener.h"
#include "loop.h"
#include "server.h"
#include "flag.h"


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Server s( "pop3d" );
    s.setup( Server::Report );
    LogClient::setup();
    s.setup( Server::Secure );
    Listener< POP3 >::create( "POP3", "", 2056 );
    s.setup( Server::Finish );

    Flag::setup();

    s.execute();
}
