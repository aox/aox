#include "global.h"
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

#include <stdlib.h>


int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::makeGlobal( ".imapdrc" );

    LogClient::setup();

    TLS::setup();
    OCClient::setup();
    Database::setup();
    Mailbox::setup();

    Log l;
    global.setLog( &l );

    log( "IMAP server started" );
    log( Test::report() );

    Listener<IMAP>::create( "IMAP", "", 2052 );

    Configuration::global()->report();
    l.commit();

    if ( Log::disastersYet() )
        exit( 1 );

    Loop::start();
}
