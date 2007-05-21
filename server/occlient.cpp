// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "occlient.h"

#include "scope.h"
#include "string.h"
#include "configuration.h"
#include "eventloop.h"
#include "endpoint.h"
#include "mailbox.h"
#include "buffer.h"
#include "query.h"
#include "flag.h"
#include "log.h"


class OCCData
    : public Garbage
{
public:
};

static class OCClient * client;


/*! \class OCClient occlient.h
    This class is responsible for interacting with the OCServer.

    Every IMAP server initiates a connection to the cluster coordination
    server by calling the static setup() function at startup. This class
    assumes responsibility for interacting with the rest of the cluster.


*/


/*! Creates an OCClient object for the fd \a s. */

OCClient::OCClient( int s )
    : Connection( s, Connection::OryxClient ), d( new OCCData )
{
    EventLoop::global()->addConnection( this );
}


/*! Connects to the configured OCD server on ocdhost.
    Expects to be called from ::main().
*/

void OCClient::setup()
{
    Endpoint e( Configuration::OcdAddress, Configuration::OcdPort );

    if ( !e.valid() )
        return;

    client = new OCClient( Connection::socket( e.protocol() ) );
    client->setBlocking( true );

    if ( client->connect( e ) < 0 ) {
        ::log( "Unable to connect to oryx cluster server " + e.string(),
               Log::Disaster );
        return;
    }

    client->setBlocking( false );
}


void OCClient::react( Event e )
{
    switch ( e ) {
    case Connect:
    case Timeout:
    case Shutdown:
        break;

    case Read:
        parse();
        break;

    case Close:
    case Error:
        if ( state() == Connecting )
            log( "Couldn't connect to ocd server.", Log::Disaster );
        EventLoop::shutdown();
        break;
    }
}


/*! Parses messages from the OCServer. */

void OCClient::parse()
{
    String * s = readBuffer()->removeLine();

    while ( s ) {
        int i = s->find( ' ' );
        String tag = s->mid( 0, i );
        int j = s->find( ' ', i+1 );
        String msg = s->mid( i+1, j-i-1 ).lower().stripCRLF();
        String arg = s->mid( j+1 ).stripCRLF();

        Scope x( new Log( Log::Server ) );

        ::log( "OCClient received " + tag + "/" + msg + " <<" + arg + ">>",
               Log::Debug );

        if ( msg == "shutdown" ) {
            ::log( "Shutting down due to ocd request" );
            EventLoop::shutdown();
        }
        else if ( msg == "mailbox" ) {
            updateMailbox( arg );
        }
        else if ( msg == "caches" ) {
            Flag::setup();
        }
        s = readBuffer()->removeLine();
    }
}


/*! This static function sends the message \a s to the OCServer. */

void OCClient::send( const String &s )
{
    if ( !client )
        setup();
    if ( !client )
        return;
    client->enqueue( "* " + s + "\n" );
    client->write();
}


/*! Parses and acts on a single mailbox update line in \a arg. A Mailbox
    update changes a single aspect of a mailbox, which may be whether it
    is deleted or what its UIDNEXT value is.

    The format is: Mailbox name quoted using String::quoted(),
    followed by a space, followed by the attribute name (deleted or
    uidnext) followed by '=', followed by the value (t or f for
    deleted, a decimal integer for uidnext).
*/

void OCClient::updateMailbox( const String & arg )
{
    uint i = arg.length();
    while ( i > 0 && arg[i] != '"' )
        i--;
    i++;
    String mailboxName = arg.mid( 0, i );
    if ( !mailboxName.isQuoted() ) {
        ::log( "Mailbox name not quoted: " + mailboxName, Log::Error );
        return;
    }
    Mailbox * m = Mailbox::obtain( mailboxName.unquoted(), true );
    if ( !m ) {
        ::log( "Mailbox name syntactically invalid: " + mailboxName.unquoted(),
               Log::Error );
        return;
    }

    uint uidnext = 0;
    int64 nextmodseq = 0;

    StringList::Iterator a( StringList::split( ' ', arg.mid( i+1 ) ) );
    while ( a ) {
        if ( *a == "new" ) {
            ::log( "OCClient announced mailbox " + m->name(), Log::Debug );
            m->setDeleted( false );
            m->refresh()->execute();
        }
        else if ( *a == "deleted" ) {
            if ( !m->deleted() )
                ::log( "OCClient deleted mailbox " + m->name(), Log::Debug );
            m->setDeleted( true );
            m->refresh()->execute();
        }
        else if ( a->startsWith( "uidnext=" ) ) {
            bool ok;
            uint n = a->mid( 8 ).number( &ok );
            if ( !ok ) {
                ::log( "Unable to parse UIDNEXT value: " + a->mid( 8 ),
                       Log::Error );
            }
            else if ( n > m->uidnext() ||
                      ( n == 1 &&
                        !Configuration::toggle( Configuration::Security ) ) ) {
                uidnext = n;
            }
        }
        else if ( a->startsWith( "nextmodseq=" ) ) {
            bool ok;
            uint n = a->mid( 11 ).number( &ok ); // XXX: eek! bigint!
            if ( !ok ) {
                ::log( "Unable to parse NEXTMODSEQ value: " + a->mid( 11 ),
                       Log::Error );
            }
            else if ( n > m->nextModSeq() ||
                      ( n == 1 &&
                        !Configuration::toggle( Configuration::Security ) ) ) {
                nextmodseq = n;
            }
        }
        else {
            ::log( "Unable to parse mailbox changes: " + arg, Log::Error );
        }
        ++a;
    }
    if ( uidnext && nextmodseq ) {
        ::log( "OCClient set mailbox " + m->name() +
               " to uidnext " + fn( uidnext ) +
               " and nextmodseq " + fn( nextmodseq ), Log::Debug );
        m->setUidnextAndNextModSeq( uidnext, nextmodseq );
    }
    else if ( uidnext ) {
        ::log( "OCClient set mailbox " + m->name() +
               " to uidnext " + fn( uidnext ), Log::Debug );
        m->setUidnext( uidnext );
    }
    else if ( nextmodseq ) {
        ::log( "OCClient set mailbox " + m->name() +
               " to nextmodseq " + fn( nextmodseq ), Log::Debug );
        m->setNextModSeq( nextmodseq );
    }
}
