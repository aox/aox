// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "server.h"

#include "pop.h"
#include "imap.h"
#include "http.h"
#include "smtp.h"
#include "sieve.h"

#include "tls.h"
#include "flag.h"
#include "schema.h"
#include "mailbox.h"
#include "listener.h"
#include "database.h"
#include "occlient.h"
#include "fieldcache.h"
#include "addresscache.h"


/*! \nodoc */

int main( int argc, char *argv[] )
{
    Scope global;

    Server s( "archiveopteryx", argc, argv );
    s.setup( Server::Report );

    Listener< IMAP >::create(
        "IMAP", Configuration::toggle( Configuration::UseImap ),
        Configuration::ImapAddress, Configuration::ImapPort,
        false
    );
    Listener< IMAPS >::create(
        "IMAPS", Configuration::toggle( Configuration::UseImaps ),
        Configuration::ImapsAddress, Configuration::ImapsPort,
        false
    );
    Listener< POP >::create(
        "POP3", Configuration::toggle( Configuration::UsePop ),
        Configuration::PopAddress, Configuration::PopPort,
        false
    );
    Listener< HTTP >::create(
        "HTTP", Configuration::toggle( Configuration::UseHttp ),
        Configuration::HttpAddress, Configuration::HttpPort,
        false
    );
    Listener< Sieve >::create(
        "Sieve", Configuration::toggle( Configuration::UseSieve ),
        Configuration::SieveAddress, Configuration::SievePort,
        false
    );
    Listener< SMTP >::create(
        "SMTP", Configuration::toggle( Configuration::UseSmtp ),
        Configuration::SmtpAddress, Configuration::SmtpPort,
        false
    );
    Listener< LMTP >::create(
        "LMTP", Configuration::toggle( Configuration::UseLmtp ),
        Configuration::LmtpAddress, Configuration::LmtpPort,
        false
    );

    Database::setup();

    s.setup( Server::Finish );

    Schema::check( &s );
    Mailbox::setup( &s );

    TlsServer::setup();
    OCClient::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    Flag::setup();
    IMAP::setup();
    POP::setup();
    Sieve::setup();

    s.run();
}
