// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "logclient.h"
#include "occlient.h"
#include "database.h"
#include "mailbox.h"
#include "listener.h"
#include "imap.h"
#include "handlers/capability.h"
#include "fieldcache.h"
#include "addresscache.h"
#include "server.h"
#include "flag.h"
#include "tls.h"
#include "injector.h"


/*! \nodoc */

int main( int argc, char *argv[] )
{
    Scope global;

    Server s( "imapd", argc, argv );
    s.setup( Server::Report );
    Listener< IMAP >::create( "IMAP", "", 143 );
    Configuration::Toggle use993( "use-imaps", false );
    if ( use993 )
        Listener< IMAPS >::create( "IMAPS", "", 993 );
    Database::setup();
    s.setup( Server::Finish );

    TlsServer::setup();
    OCClient::setup();
    Mailbox::setup();
    Capability::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    Flag::setup();
    IMAP::setup();
    Injector::setup();

    s.execute();
}
