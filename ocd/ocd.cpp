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
    Listener< OCServer >::create( "Cluster coordination", "", 2050 );
    Listener< OCAdmin >::create( "Cluster administration", "", 2051 );

    s.execute();
}
