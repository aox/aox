#include "global.h"
#include "arena.h"
#include "scope.h"
#include "test.h"
#include "configuration.h"
#include "log.h"
#include "occlient.h"
#include "database.h"
#include "mailbox.h"
#include "listener.h"
#include "smtp.h"
#include "loop.h"
#include "tls.h"

#include <stdlib.h>


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::makeGlobal( ".smtpdrc" );

    TLS::setup();
    OCClient::setup();
    Database::setup();
    Mailbox::setup();

    Log l;
    global.setLog( &l );

    log( "SMTP server started" );
    log( Test::report() );

    Listener<SMTP>::create( "SMTP", "", 2025 );
    Listener<LMTP>::create( "LMTP", "", 2026 );

    Configuration::global()->report();
    l.commit();

    if ( Log::disastersYet() )
        exit( 1 );

    Loop::start();
}
