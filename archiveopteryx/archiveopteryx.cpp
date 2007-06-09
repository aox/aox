// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "server.h"

#include "pop.h"
#include "imap.h"
#include "http.h"
#include "smtp.h"
#include "managesieve.h"

#include "tls.h"
#include "flag.h"
#include "mailbox.h"
#include "listener.h"
#include "database.h"
#include "occlient.h"
#include "fieldcache.h"
#include "addresscache.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


/*! \nodoc */


int main( int argc, char *argv[] )
{
    Scope global;

    Server s( "archiveopteryx", argc, argv );
    s.setup( Server::Report );

    if ( Configuration::toggle( Configuration::UseSmtp ) ||
         Configuration::toggle( Configuration::UseLmtp ) ) {
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
            if ( Configuration::present( Configuration::MessageCopyDir ) )
                log( "Disregarding message-copy-directory (value " + mcd +
                     ") because message-copy is set to none " );
        }
        else {
            log( "Invalid value for message-copy: " + mc, Log::Disaster );
        }
    }


    String sA( Configuration::text( Configuration::SmartHostAddress ) );
    uint sP( Configuration::scalar( Configuration::SmartHostPort ) );

    if ( Configuration::toggle( Configuration::UseSmtp ) &&
         Configuration::scalar( Configuration::SmtpPort ) == sP &&
         ( Configuration::text( Configuration::SmtpAddress ) == sA ||
           ( Configuration::text( Configuration::SmtpAddress ) == "" &&
             sA == "127.0.0.1" ) ) )
    {
        log( "smarthost-address/port are the same as smtp-address/port",
             Log::Disaster );
    }

    if ( Configuration::toggle( Configuration::UseLmtp ) &&
         Configuration::scalar( Configuration::LmtpPort ) == sP &&
         ( Configuration::text( Configuration::LmtpAddress ) == sA ||
           ( Configuration::text( Configuration::LmtpAddress ) == "" &&
             sA == "127.0.0.1" ) ) )
    {
        log( "smarthost-address/port are the same as lmtp-address/port",
             Log::Disaster );
    }

    if ( Configuration::toggle( Configuration::UseSmtpSubmit ) &&
         Configuration::scalar( Configuration::SmtpSubmitPort ) == sP &&
         ( Configuration::text( Configuration::SmtpSubmitAddress ) == sA ||
           ( Configuration::text( Configuration::SmtpSubmitAddress ) == "" &&
             sA == "127.0.0.1" ) ) )
    {
        log( "smarthost-address/port are the same as "
             "smtp-submit-address/port", Log::Disaster );
    }

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
    Listener< ManageSieve >::create(
        "Sieve", Configuration::toggle( Configuration::UseSieve ),
        Configuration::ManageSieveAddress, Configuration::ManageSievePort,
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
    Listener< SMTPSubmit >::create(
        "SMTP-Submit", Configuration::toggle( Configuration::UseSmtpSubmit ),
        Configuration::SmtpSubmitAddress, Configuration::SmtpSubmitPort,
        false
        );
    Listener< SMTPS >::create(
        "SMTPS", Configuration::toggle( Configuration::UseSmtps ),
        Configuration::SmtpsAddress, Configuration::SmtpsPort,
        false
        );

    s.setup( Server::LogStartup );

    Database::setup();

    s.setup( Server::Finish );

    Database::checkSchemaRevision( &s );
    if ( Configuration::toggle( Configuration::Security ) )
        Database::checkAccess( &s );
    Mailbox::setup( &s );

    TlsServer::setup();
    OCClient::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    Flag::setup();
    IMAP::setup();

    s.run();
}
