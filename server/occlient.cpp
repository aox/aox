#include "occlient.h"

#include "string.h"
#include "configuration.h"
#include "endpoint.h"
#include "buffer.h"
#include "loop.h"
#include "log.h"


class OCCData {
public:
};

static class OCClient *client = 0;


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
    Loop::addConnection( this );
}


/*! \reimp */

OCClient::~OCClient()
{
    Loop::removeConnection( this );
}


/*! Connects to the configured OCD server on ocdhost.
    Expects to be called from ::main().
*/

void OCClient::setup()
{
    Configuration::Text ocdHost( "ocdhost", "127.0.0.1" );
    Configuration::Scalar ocdPort( "ocdport", 2050 );
    Endpoint e( ocdHost, ocdPort );

    if ( !e.valid() ) {
        log( Log::Disaster,
             "Invalid ocdhost address <" + ocdHost + "> port <" +
             fn( ocdPort ) + ">\n" );
        return;
    }

    client = new OCClient( Connection::socket( e.protocol() ) );
    client->setBlocking( true );

    if ( client->connect( e ) < 0 ) {
        log( Log::Disaster, "Unable to connect to ocdhost " + e.string() + "\n" );
        return;
    }

    client->setBlocking( false );
}


/*! \reimp */

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
        Loop::shutdown();
        break;
    }
}


/*! Parses messages from the CCServer. */

void OCClient::parse()
{
    String *s = readBuffer()->removeLine();

    if ( !s )
        return;

    String r = s->lower();

    if ( r == "shutdown" )
        Loop::shutdown();
}
