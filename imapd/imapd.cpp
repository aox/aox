#include "arena.h"
#include "scope.h"
#include "test.h"
#include "configuration.h"
#include "logclient.h"
#include "occlient.h"
#include "database.h"
#include "mailbox.h"
#include "listener.h"
#include "imap.h"
#include "loop.h"
#include "tls.h"
#include "handlers/capability.h"
#include "fieldcache.h"
#include "addresscache.h"
#include "mechanism.h"

#include <stdlib.h>


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::setup( "mailstore.conf", "imapd.conf" );

    Loop::setup();

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    TLS::setup();
    OCClient::setup();
    Database::setup();
    Mailbox::setup();
    Capability::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    SaslMechanism::setup();

    log( Test::report() );

    Listener< IMAP >::create( "IMAP", "", 2052 );

    Configuration::report();
    l.commit();

    if ( Log::disastersYet() )
        exit( 1 );

    Loop::start();
}
