// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "arena.h"
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
    Arena firstArena;
    Scope global( &firstArena );

    Server s( "imapd", argc, argv );
    s.setup( Server::Report );
    Listener< IMAP >::create( "IMAP", "", 143 );
    s.setup( Server::Finish );

    TlsServer::setup();
    OCClient::setup();
    Database::setup();
    Mailbox::setup();
    Capability::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    Flag::setup();
    IMAP::setup();
    Injector::setup();

    s.execute();
}
