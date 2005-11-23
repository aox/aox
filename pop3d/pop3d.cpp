// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "server.h"
#include "mailbox.h"
#include "occlient.h"
#include "logclient.h"
#include "addresscache.h"
#include "fieldcache.h"
#include "listener.h"
#include "database.h"
#include "schema.h"
#include "flag.h"
#include "tls.h"
#include "pop.h"


/*! \nodoc */


int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "pop3d", argc, argv );
    s.setup( Server::Report );

    Listener< POP >::create(
        "POP3", Configuration::toggle( Configuration::UsePop ),
        Configuration::PopAddress, Configuration::PopPort,
        false
    );

    Database::setup();

    s.setup( Server::Finish );

    Schema::check( &s );
    Mailbox::setup( &s );

    TlsServer::setup();
    OCClient::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    Flag::setup();
    POP::setup();

    s.run();
}
