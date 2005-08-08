// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "configuration.h"
#include "logclient.h"
#include "occlient.h"
#include "database.h"
#include "mailbox.h"
#include "listener.h"
#include "http.h"
#include "fieldcache.h"
#include "addresscache.h"
#include "server.h"
#include "injector.h"
#include "tls.h"
#include "configuration.h"
#include "schema.h"


/*! \nodoc */

int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "httpd", argc, argv );
    s.setup( Server::Report );

    Listener< HTTP >::create(
        "HTTP", Configuration::toggle( Configuration::UseHttp ),
        Configuration::HttpAddress, Configuration::HttpPort,
        false
    );

    Database::setup();

    s.setup( Server::Finish );

    s.waitFor( Schema::check( &s ) );

    TlsServer::setup();
    OCClient::setup();
    Mailbox::setup();
    AddressCache::setup();
    FieldNameCache::setup();

    s.run();
}
