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

    This is the Logger that's used throughout most of the Oryx
    system. All programs that want to use the regular log server must
    call LogClient::setup() at startup.

    The 
*/

/*! Creates a new LogClient. This constructor is usable only via setup(). */

LogClient::LogClient()
    : Logger(), c( 0 )
{
}


/*! \reimp */

void LogClient::send( const String &s )
{
    c->enqueue( s );
}


/*! Connects to the configured log server and creates a singleton
    Logger talking to that server.

    If setup() cannot connect to a log server, it brutally exits the
    application.
*/


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

    LogClient *client = new LogClient;
    client->c = new LogClientHelper( Connection::socket( e.protocol() ) );
    client->c->setBlocking( true );
    if ( client->c->connect( e ) < 0 ) {
        fprintf( stderr, "LogClient: Unable to connect to log server %s\n",
                 String(e).cstr() );
        perror( "LogClient: connect() returned" );
        exit( -1 );
    }

    client->c->setBlocking( false );
    Loop::addConnection( client->c );
}


/*! \class LogClientHelper logclient.h

  The LogClientHelper is a simple write-only Connection used by the
  LogClient. It's usable by no other class, and reacts to reads by
  shutting down the application.

  This class exists only so that LogClient can avoid multiple
  inheritance.
*/


/*! \reimp */

void LogClientHelper::react( Event e )
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
        // perhaps we should log something first? but how?
        Loop::shutdown();
        break;
    }
}


