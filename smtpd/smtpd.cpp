#include "arena.h"
#include "scope.h"
#include "test.h"
#include "configuration.h"
#include "logclient.h"
#include "log.h"
#include "tls.h"
#include "occlient.h"
#include "database.h"
#include "mailbox.h"
#include "listener.h"
#include "smtp.h"
#include "loop.h"
#include "addresscache.h"

// exit
#include <stdlib.h>


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::setup( "mailstore.conf", "smtpd.conf" );

    Loop::setup();

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    TLS::setup();
    OCClient::setup();
    Database::setup();
    Mailbox::setup();
    AddressCache::setup();

    log( "SMTP server version " +
         Configuration::compiledIn( Configuration::Version ) +
         " started" );
    log( Test::report() );

    Configuration::Toggle useSmtp( "use-smtp", false );
    if ( useSmtp ) {
        Configuration::Scalar port( "smtp-port", 25 );
        Configuration::Text address( "smtp-host", "" );
        Listener< SMTP >::create( "SMTP", address, port );
    }

    Configuration::Toggle useLmtp( "use-lmtp", true );
    if ( useLmtp ) {
        Configuration::Scalar port( "lmtp-port", 2026 );
        Configuration::Text address( "lmtp-host", "127.0.0.1" );
        Listener< LMTP >::create( "LMTP", address, port );
    }

    Configuration::report();
    l.commit();

    if ( Log::disastersYet() )
        exit( 1 );

    Loop::start();
}
