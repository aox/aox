// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "arena.h"
#include "scope.h"
#include "configuration.h"
#include "logclient.h"
#include "occlient.h"
#include "database.h"
#include "mailbox.h"
#include "listener.h"
#include "smtp.h"
#include "fieldcache.h"
#include "addresscache.h"
#include "server.h"
#include "injector.h"


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Server s( "smtpd" );
    s.setup( Server::Report );
    LogClient::setup();

    Configuration::Toggle useSmtp( "use-smtp", false );
    if ( useSmtp )
        Listener< SMTP >::create( "SMTP", "", 25 );

    Configuration::Toggle useLmtp( "use-lmtp", true );
    if ( useLmtp )
        Listener< LMTP >::create( "LMTP", "127.0.0.1", 2026 );

    s.setup( Server::Secure );
    s.setup( Server::Finish );

    OCClient::setup();
    Database::setup();
    Mailbox::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    Injector::setup();

    s.execute();
}
