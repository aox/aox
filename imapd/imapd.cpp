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
#include "schema.h"


/*! \nodoc */

int main( int argc, char *argv[] )
{
    Scope global;

    Server s( "imapd", argc, argv );
    s.setup( Server::Report );

    Listener< IMAP >::create(
        "IMAP", Configuration::toggle( Configuration::UseImap ),
        Configuration::ImapAddress, Configuration::ImapPort,
        false
    );
    Listener< IMAPS >::create(
        "IMAPS", Configuration::toggle( Configuration::UseImaps ),
        Configuration::ImapsAddress, Configuration::ImapsPort,
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
    IMAP::setup();

    s.run();
}
