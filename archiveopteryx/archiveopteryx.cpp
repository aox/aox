// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "scope.h"
#include "server.h"

#include "pop.h"
#include "imap.h"
#include "smtp.h"
#include "graph.h"

#include "tlsthread.h"
#include "flag.h"
#include "event.h"
#include "cache.h"
#include "mailbox.h"
#include "listener.h"
#include "database.h"
#include "dbsignal.h"
#include "selector.h"
#include "managesieve.h"
#include "spoolmanager.h"
#include "entropy.h"
#include "egd.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h> // exit()


/*! \nodoc */


class StartupWatcher
    : public EventHandler
{
public:
    StartupWatcher(): EventHandler() {}
    void execute() {
        if ( Log::disastersYet() )
            ::exit( 1 );
        EventLoop::global()->setStartup( false );
    }
};


class ConnectionObliterator
    : public EventHandler
{
public:
    ConnectionObliterator()
        : EventHandler() {
        (void)new DatabaseSignal( "obliterated", this );
    }
    void execute() {
        List<Connection>::Iterator i( EventLoop::global()->connections() );
        while ( i ) {
            Connection * c = i;
            ++i;
            if ( !c->hasProperty( Connection::Listens ) &&
                 !c->hasProperty( Connection::Internal ) ) {
                Scope x( c->log() );
                log( "The database was obliterated" );
                c->close();
            }
        }
        EventLoop::freeMemorySoon();
        Cache::clearAllCaches( true );
    }
};


class ArchiveopteryxEventLoop
    : public EventLoop
{
public:
    ArchiveopteryxEventLoop() {}
    ~ArchiveopteryxEventLoop();

    void freeMemory();
};


ArchiveopteryxEventLoop::~ArchiveopteryxEventLoop()
{
}


void ArchiveopteryxEventLoop::freeMemory()
{
    EventLoop::freeMemory();
    if ( Allocator::adminLikelyHappy() )
        return;
    // unhappy admin. make the parent replace this process with another.
    if ( ::fork() > 0 )
        ::exit( 0 );
    // the process watcher will notice that the parent fork exited,
    // and start a replacement. in the child, we shut down fairly
    // quickly.
    stop( 20 );
}



int main( int argc, char *argv[] )
{
    Scope global;

    Server s( "archiveopteryx", argc, argv );
    EventLoop::setup( new ArchiveopteryxEventLoop );
    s.setup( Server::Report );

    bool security( Configuration::toggle( Configuration::Security ) );
    EString root( Configuration::text( Configuration::JailDir ) );

    if ( Configuration::toggle( Configuration::UseSmtp ) ||
         Configuration::toggle( Configuration::UseLmtp ) )
    {
        EString mc( Configuration::text( Configuration::MessageCopy ) );
        EString mcd( Configuration::text( Configuration::MessageCopyDir ) );
        if ( mc == "all" || mc == "errors" || mc == "delivered" ) {
            struct stat st;
            if ( mcd.isEmpty() )
                log( "message-copy-directory not set", Log::Disaster );
            else if ( ::stat( mcd.cstr(), &st ) < 0 || !S_ISDIR( st.st_mode ) )
                log( "Inaccessible message-copy-directory: " + mcd,
                     Log::Disaster );
            else if ( security && !mcd.startsWith( root ) )
                log( "message-copy-directory must be under jail directory " +
                     root, Log::Disaster );
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


    EString sA( Configuration::text( Configuration::SmartHostAddress ) );
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


    EString app =
        Configuration::text( Configuration::AllowPlaintextPasswords ).lower();
    if ( !( app == "always" || app == "never" ) )
        ::log( "Unknown value for allow-plaintext-passwords: " + app,
               Log::Disaster );
    if ( app == "never" &&
         Configuration::toggle( Configuration::UseTls ) == false &&
         Configuration::toggle( Configuration::AuthCramMd5 ) == false &&
         Configuration::toggle( Configuration::AuthDigestMd5 ) == false )
        ::log( "allow-plaintext-passwords is 'never' and use-tls is 'false', "
               "but only plaintext authentication mechanisms are allowed",
               Log::Disaster );

    EString apa =
        Configuration::text( Configuration::AllowPlaintextAccess ).lower();
    if ( !( apa == "always" || apa == "localhost" || apa == "never" ) )
        ::log( "Unknown value for allow-plaintext-access: " + apa,
               Log::Disaster );
    if ( apa == "never" &&
         Configuration::toggle( Configuration::UseTls ) == false )
        ::log( "allow-plaintext-access is 'never', but use-tls is 'false'",
               Log::Disaster );

    // set up an EGD server for openssl
    Entropy::setup();
    EString egd( root );
    if ( !egd.endsWith( "/" ) )
        egd.append( "/" );
    egd.append( "var/run/egd-pool" );
    (void)new Listener< EntropyProvider >( Endpoint( egd, 0 ), "EGD" );
    if ( !security ) {
        struct stat st;
        if ( stat( "/var/run/edg-pool", &st ) < 0 ) {
            log( "Security is disabled and /var/run/edg-pool does not exist. "
                 "Creating it just in case openssl wants to access it." );
            (void)new Listener< EntropyProvider >(
                Endpoint( "/var/run/edg-pool", 0 ), "EGD(/)" );
        }
    }
    if ( ::chmod( egd.cstr(), 0666 ) < 0 )
        log( "Could not grant r/w access to EGD socket", Log::Disaster );

    Listener< IMAP >::create(
        "IMAP", Configuration::toggle( Configuration::UseImap ),
        Configuration::ImapAddress, Configuration::ImapPort
    );
    Listener< IMAPS >::create(
        "IMAPS", Configuration::toggle( Configuration::UseImaps ),
        Configuration::ImapsAddress, Configuration::ImapsPort
    );
    Listener< POP >::create(
        "POP3", Configuration::toggle( Configuration::UsePop ),
        Configuration::PopAddress, Configuration::PopPort
    );
    Listener< POPS >::create(
        "POP3S", Configuration::toggle( Configuration::UsePops ),
        Configuration::PopsAddress, Configuration::PopsPort
    );
    Listener< ManageSieve >::create(
        "Sieve", Configuration::toggle( Configuration::UseSieve ),
        Configuration::ManageSieveAddress, Configuration::ManageSievePort
    );
    Listener< SMTP >::create(
        "SMTP", Configuration::toggle( Configuration::UseSmtp ),
        Configuration::SmtpAddress, Configuration::SmtpPort
    );
    Listener< LMTP >::create(
        "LMTP", Configuration::toggle( Configuration::UseLmtp ),
        Configuration::LmtpAddress, Configuration::LmtpPort
    );
    Listener< SMTPSubmit >::create(
        "SMTP-Submit", Configuration::toggle( Configuration::UseSmtpSubmit ),
        Configuration::SmtpSubmitAddress, Configuration::SmtpSubmitPort
    );
    Listener< SMTPS >::create(
        "SMTPS", Configuration::toggle( Configuration::UseSmtps ),
        Configuration::SmtpsAddress, Configuration::SmtpsPort
    );

    if ( Configuration::toggle( Configuration::UseTls ) ) {
        TlsThread::setup();
    }

    s.setup( Server::LogStartup );

    Listener< GraphDumper >::create(
        "Statistics", Configuration::toggle( Configuration::UseStatistics ),
        Configuration::StatisticsAddress, Configuration::StatisticsPort
    );

    EventLoop::global()->setMemoryUsage(
        1024 * 1024 * Configuration::scalar( Configuration::MemoryLimit ) );

    Database::setup();

    s.setup( Server::Finish );

    StartupWatcher * w = new StartupWatcher;

    Database::checkSchema( w );
    if ( security )
        Database::checkAccess( w );
    EventLoop::global()->setStartup( true );
    Mailbox::setup( w );

    SpoolManager::setup();
    Selector::setup();
    Flag::setup();
    IMAP::setup();

    if ( !security )
        (void)new ConnectionObliterator;

    s.run();
}
