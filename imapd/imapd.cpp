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
#include "imap.h"
#include "smtp.h"
#include "loop.h"

#include <stdlib.h>


int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::makeGlobal( ".imapdrc" );

    Log::setup();
    OCClient::setup();
    Database::setup();
    Mailbox::setup();

    Log l;
    global.setLog( &l );

    log( "IMAP server started" );
    log( Test::report() );

    // should we pick this up from the config file?
    Listener<IMAP>::create( "IMAP", "", 2052 );
    Listener<SMTP>::create( "SMTP", "", 2025 );
    Listener<LMTP>::create( "LMTP", "", 2026 );

    Configuration::global()->report();
    l.commit();

    if ( Log::disastersYet() )
        exit( 1 );

    Loop::start();
}
