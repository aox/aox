#include "arena.h"
#include "scope.h"
#include "listener.h"
#include "ocserver.h"
#include "ocadmin.h"
#include "logclient.h"
#include "server.h"

#include <stdlib.h>


/*! \nodoc */

int main()
{
    Arena firstArena;
    Scope global( &firstArena );

    Server s( "ocd" );
    s.setup( Server::Report );
    LogClient::setup();
    s.setup( Server::Secure );
    Listener< OCServer >::create( "ocd", "127.0.0.1", 2050 );
    Listener< OCAdmin >::create( "ocadmin", "", 2051 );

    s.execute();
}
