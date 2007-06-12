// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "event.h"
#include "string.h"
#include "allocator.h"
#include "stderrlogger.h"
#include "configuration.h"
#include "addresscache.h"
#include "permissions.h"
#include "fieldcache.h"
#include "logclient.h"
#include "eventloop.h"
#include "injector.h"
#include "occlient.h"
#include "mailbox.h"
#include "message.h"
#include "query.h"
#include "file.h"
#include "user.h"
#include "log.h"

#include <stdlib.h>
#include <stdio.h>

// time, ctime
#include <time.h>
// all the exit codes
#include <sysexits.h>


static void quit( uint s, const String & m )
{
    if ( !m.isEmpty() )
        fprintf( stderr, "deliver: %s\n", m.cstr() );
    exit( s );
}


class Deliverator
    : public EventHandler
{
public:
    Query * q;
    Injector * i;
    Message * m;
    String mbn;
    String un;
    Permissions * p;
    Mailbox * mb;

    Deliverator( Message * message,
                 const String & mailbox, const String & user )
        : q( 0 ), i( 0 ), m( message ), mbn( mailbox ), un( user ),
          p( 0 ), mb( 0 )
    {
        Allocator::addEternal( this, "deliver object" );
        q = new Query( "select al.mailbox, n.name as namespace, u.login "
                       "from aliases al "
                       "join addresses a on (al.address=a.id) "
                       "left join users u on (al.id=u.alias) "
                       "left join namespaces n on (u.parentspace=n.id) "
                       "where (lower(a.localpart)=$1 and lower(a.domain)=$2) "
                       "or (lower(u.login)=$3)", this );
        if ( user.contains( '@' ) ) {
            int at = user.find( '@' );
            q->bind( 1, user.mid( 0, at ).lower() );
            q->bind( 2, user.mid( at + 1 ).lower() );
        }
        else {
            q->bindNull( 1 );
            q->bindNull( 2 );
        }
        q->bind( 2, user.lower() );
        q->execute();
    }

    virtual ~Deliverator()
    {
        quit( EX_TEMPFAIL, "Delivery object unexpectedly deleted" );
    }

    void execute()
    {
        if ( q && !q->done() )
            return;

        if ( q && q->done() && !p ) {
            Row * r = q->nextRow();
            q = 0;
            if ( !r )
                quit( EX_NOUSER, "No such user: " + un );
            if ( !r->isNull( "login" ) &&
                 r->getString( "login" ) == "anonymous" )
                quit( EX_DATAERR, "Cannot deliver to the anonymous user" );
            if ( mbn.isEmpty() ) {
                mb = Mailbox::find( r->getInt( "mailbox" ) );
            }
            else {
                String pre;
                if ( !r->isNull( "namespace" ) && !mbn.startsWith( "/" ) )
                    pre = r->getString( "namespace" ) + "/" +
                          r->getString( "login" ) + "/";
                mb = Mailbox::find( pre + mbn );
                User * u = new User;
                u->setLogin( "anyone" );
                if ( mb )
                    p = new Permissions( mb, u, this );
            }
            if ( !mb )
                quit( EX_CANTCREAT, "No such mailbox" );
        }

        if ( p && !p->ready() )
            return;

        if ( p && !p->allowed( Permissions::Post ) )
            quit( EX_NOPERM,
                  "User 'anyone' does not have 'p' right on mailbox " +
                  mbn.quoted( '\'' ) );

        if ( !i ) {
            i = new Injector( m, this );
            i->setMailbox( mb );
            i->execute();
        }

        if ( !i->done() )
            return;

        if ( i->failed() )
            quit( EX_SOFTWARE, "Injection error: " + i->error() );

        i->announce();
        i = 0;
        EventLoop::shutdown();
    }
};


int main( int argc, char *argv[] )
{
    Scope global;

    String sender;
    String mailbox;
    String recipient;
    String filename;
    bool error = false;
    int verbose = 0;

    int n = 1;
    while ( n < argc ) {
        if ( argv[n][0] == '-' ) {
            switch ( argv[n][1] ) {
            case 'f':
                if ( argc - n > 1 )
                    sender = argv[++n];
                break;

            case 't':
                if ( argc - n > 1 )
                    mailbox = argv[++n];
                break;

            case 'v':
                {
                    int i = 1;
                    while ( argv[n][i] == 'v' ) {
                        verbose++;
                        i++;
                    }
                    if ( argv[n][i] != '\0' )
                        error = true;
                }
                break;

            default:
                error = true;
                break;
            }
        }
        else if ( recipient.isEmpty() ) {
            recipient = argv[n];
        }
        else if ( filename.isEmpty() ) {
            filename = argv[n];
        }
        else {
            error = true;
        }
        n++;
    }

    if ( error || recipient.isEmpty() ) {
        fprintf( stderr,
                 "Syntax: deliver [-v] [-f sender] recipient [filename]\n" );
        exit( -1 );
    }

    String contents;
    if ( filename.isEmpty() ) {
        char s[128];
        while ( fgets( s, 128, stdin ) != 0 )
            contents.append( s );
    }
    else {
        File message( filename );
        if ( !message.valid() ) {
            fprintf( stderr, "Unable to open message file %s\n",
                     filename.cstr() );
            exit( -1 );
        }
        contents = message.contents();
    }

    Configuration::setup( "archiveopteryx.conf" );

    Message * message = new Message( contents );
    if ( !message->error().isEmpty() ) {
        fprintf( stderr,
                 "Message parsing failed: %s", message->error().cstr( ) );
        exit( EX_DATAERR );
    }

    if ( verbose > 0 )
        fprintf( stderr, "Sending to <%s>\n", recipient.cstr() );

    EventLoop::setup();
    Database::setup( 1 );
    Log * l = new Log( Log::General );
    Allocator::addEternal( l, "delivery log" );
    global.setLog( l );
    Allocator::addEternal( new StderrLogger( "deliver", verbose ),
                           "log object" );

    Configuration::report();
    Mailbox::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    OCClient::setup();
    (void)new Deliverator( message, mailbox, recipient );
    EventLoop::global()->start();

    return 0;
}
