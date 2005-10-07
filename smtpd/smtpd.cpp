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
#include "schema.h"
#include "file.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


/*! \nodoc */


int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "smtpd", argc, argv );
    s.setup( Server::Report );

    String mc( Configuration::text( Configuration::MessageCopy ) );
    String mcd( Configuration::text( Configuration::MessageCopyDir ) );
    if ( mc == "all" || mc == "errors" || mc == "delivered" ) {
        struct stat st;
        if ( mcd.isEmpty() )
            log( "message-copy-directory not set", Log::Disaster );
        else if ( ::stat( mcd.cstr(), &st ) < 0 || !S_ISDIR( st.st_mode ) )
            log( "Inaccessible message-copy-directory: " + mcd,
                 Log::Disaster );
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

    Schema::check( &s );
    Mailbox::setup( &s );

    TlsServer::setup();
    OCClient::setup();
    AddressCache::setup();
    FieldNameCache::setup();

    s.run();
}
