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
#include "log.h"


/*! \nodoc */

int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "smtpd", argc, argv );
    s.setup( Server::Report );

    String mc( Configuration::text( Configuration::MessageCopy ) );
    String mcd( Configuration::text( Configuration::MessageCopyDir ) );
    if ( mc == "all" || mc == "errors" || mc == "delivered" ) {
        if ( mcd.isEmpty() )
            log( "message-copy-directory not set", Log::Disaster );
        s.setChrootMode( Server::MessageCopyDir );
    }
    else if ( mc == "none" ) {
        if ( !mcd.isEmpty() )
            log( "Disregarding message-copy-directory "
                 "because message-copy is set to none " );
    }
    else {
        log( "Invalid value for message-copy: " + mc, Log::Disaster );
    }

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

    TlsServer::setup();
    OCClient::setup();
    Mailbox::setup();
    AddressCache::setup();
    FieldNameCache::setup();

    s.execute();
}
