// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "logclient.h"
#include "pop3.h"
#include "listener.h"
#include "database.h"
#include "loop.h"
#include "server.h"
#include "flag.h"


/*! \nodoc */

int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "pop3d", argc, argv );
    s.setup( Server::Report );
    Listener< POP3 >::create( "POP3",
                              Configuration::Pop3Address,
                              Configuration::Pop3Port );
    s.setup( Server::Finish );
    Database::setup();
    Flag::setup();
    s.execute();
}
