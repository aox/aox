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

// exit
#include <stdlib.h>


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::setup( "mailstore.conf", "smtpd.conf" );

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    TLS::setup();
    OCClient::setup();
    Database::setup();
    Mailbox::setup();

    log( "SMTP server started" );
    log( Test::report() );

    Listener< SMTP >::create( "SMTP", "", 2025 );
    Listener< LMTP >::create( "LMTP", "", 2026 );

    Configuration::report();
    l.commit();

    if ( Log::disastersYet() )
        exit( 1 );

    Loop::start();
}
