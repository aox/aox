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


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Server s( "smtpd" );
    s.setup( Server::Report );
    LogClient::setup();
    s.setup( Server::Secure );

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

    s.setup( Server::Finish );

    OCClient::setup();
    Database::setup();
    Mailbox::setup();
    AddressCache::setup();
    FieldNameCache::setup();

    Loop::start();
}
