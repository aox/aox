#include "occlient.h"

#include "string.h"
#include "configuration.h"
#include "endpoint.h"
#include "buffer.h"
#include "loop.h"

#include <stdlib.h>
#include <stdio.h>
#include <sysexits.h>


class OCCData {
public:
};

static class OCClient *client = 0;


/*! \class OCClient occlient.h
    This class is responsible for interacting with the CCServer.

    Every IMAP server initiates a connection to the cluster coordination
    server by calling the static setup() function at startup. This class
    assumes responsibility for interacting with the rest of the cluster.
*/


/*! \reimp */

OCClient::OCClient( int s )
    : Connection( s ), d( new OCCData )
{
}


/*! Connects to OCD if the ocdhost configuration variable is set.
    Expects to be called from ::main().
*/

void OCClient::setup()
{
    Configuration::Text ocdHost( "ocdhost", "" );
    Configuration::Scalar ocdPort( "ocdport", 2050 );

    if ( ((String)ocdHost).isEmpty() )
        return;

    Endpoint e( ocdHost, ocdPort );

    if ( !e.valid() ) {
        fprintf( stderr, "OCClient: Unable to parse address <%s> port %d\n",
                 ((String)ocdHost).cstr(), (int)ocdPort );
        exit( EX_USAGE );
    }

    client = new OCClient( Connection::socket( e.protocol() ) );
    client->setBlocking( true );
    if ( client->connect( e ) < 0 ) {
        fprintf( stderr, "OCClient: Unable to connect to OCD %s\n",
                 String(e).cstr() );
        perror( "OCClient: connect() returned" );
        exit( EX_UNAVAILABLE );
    }

    client->setBlocking( false );
    Loop::addConnection( client );
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
