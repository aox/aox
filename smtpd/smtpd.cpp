// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
#include "tls.h"
#include "configuration.h"


/*! \nodoc */

int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "smtpd", argc, argv );

    s.setup( Server::Report );

    if ( Configuration::toggle( Configuration::UseSmtp ) )
        Listener< SMTP >::create( "SMTP",
                                  Configuration::SmtpAddress,
                                  Configuration::SmtpPort );

    if ( Configuration::toggle( Configuration::UseLmtp ) )
        Listener< LMTP >::create( "LMTP",
                                  Configuration::LmtpAddress,
                                  Configuration::LmtpPort );

    Database::setup();

    s.setup( Server::Finish );

    TlsServer::setup();
    OCClient::setup();
    Mailbox::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    Injector::setup();

    s.execute();
}
