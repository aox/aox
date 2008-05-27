// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "occlient.h"

#include "scope.h"
#include "cache.h"
#include "string.h"
#include "configuration.h"
#include "eventloop.h"
#include "endpoint.h"
#include "mailbox.h"
#include "buffer.h"
#include "query.h"
#include "flag.h"
#include "log.h"
#include "utf.h"


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
