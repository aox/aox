#include "logclient.h"

#include "loop.h"
#include "string.h"
#include "configuration.h"

// exit, perror
#include <stdlib.h>
// fprintf, stderr
#include <stdio.h>


/*! \class LogClient logclient.h
    A Logger subclass that talks to our log server. (LogdClient)
*/

/*! Creates a new LogClient with the fd \a fd. */

LogClient::LogClient( int fd )
    : Logger(), Connection( fd )

{
}


/*! \reimp */

void LogClient::react( Event e )
{
    // The log server isn't supposed to send us anything.
    switch ( e ) {
    case Connect:
    case Timeout:
    case Shutdown:
        break;
    case Read:
    case Close:
    case Error:
        Loop::shutdown();
        break;
    }
}


/*! \reimp */

void LogClient::send( const String &s )
{
    enqueue( s );
}


void LogClient::setup()
{
    Configuration::Text logHost( "loghost", "127.0.0.1" );
    Configuration::Scalar logPort( "logport", 2054 );
    Endpoint e( logHost, logPort );

    if ( !e.valid() ) {
        fprintf( stderr, "LogClient: Unable to parse address <%s> port %d\n",
                 ((String)logHost).cstr(), (int)logPort );
        exit( -1 );
    }

    LogClient *client = new LogClient( Connection::socket( e.protocol() ) );
    client->setBlocking( true );
    if ( client->connect( e ) < 0 ) {
        fprintf( stderr, "LogClient: Unable to connect to log server %s\n",
                 String(e).cstr() );
        perror( "LogClient: connect() returned" );
        exit( -1 );
    }

    client->setBlocking( false );
    Loop::addConnection( client );
}
