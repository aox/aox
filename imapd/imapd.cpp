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

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Server s( "imapd" );
    s.setup( Server::Report );
    LogClient::setup();
    Listener< IMAP >::create( "IMAP", "", 2052 );
    s.setup( Server::Secure );
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
