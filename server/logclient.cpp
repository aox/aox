// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "logclient.h"

#include "loop.h"
#include "string.h"
#include "server.h"
#include "connection.h"
#include "configuration.h"

// exit, perror
#include <stdlib.h>
// fprintf, stderr
#include <stdio.h>


// This is our connection to the log server.
class LogClientHelper
    : public Connection
{
public:
    LogClientHelper( int fd, const Endpoint & e, Logger *client )
        : Connection( fd, Connection::LogClient ),
          logServer( e ), owner( client )
    {
    }

    ~LogClientHelper()
    {
        Loop::removeConnection( this );
        delete owner;
        owner = 0;
    }

    void reconnect() {
        if ( state() != Invalid && state() != Inactive )
            return;

        // XXX: Should this connection still be in the Loop?
        // I don't think so. -- AMS
        Loop::removeConnection( this );
        connect( logServer );
        Loop::addConnection( this );
    }

    // The log server isn't supposed to send us anything.
    void react( Event e ) {
        switch ( e ) {
        case Connect:
        case Timeout:
        case Shutdown:
            break;
        case Read:
        case Close:
        case Error:
            // If it does, we shutdown after deactivating the LogClient.
            // XXX: We shouldn't be doing this if reconnect() is to do
            // something useful. Should fix later. -- AMS
            delete owner;
            owner = 0;
            Loop::shutdown();
            break;
        }
    }

private:
    Endpoint logServer;
    Logger *owner;
};


/*! \class LogClient logclient.h
    A Logger subclass that talks to our log server. (LogdClient)

    This is the Logger that's used throughout most of the Oryx system.
    All programs that want to use the regular log server must call
    LogClient::setup() at startup.
*/

/*! Creates a new LogClient.
    This constructor is usable only via setup().
*/

LogClient::LogClient()
    : Logger()
{
}


void LogClient::send( const String &s )
{
    c->reconnect();
    c->enqueue( s );
    if ( c->state() == Connection::Connected )
        c->write();
}


/*! Connects to the configured log server and creates a singleton
    Logger named \a name talking to that server.

    If setup() cannot connect to a log server, it brutally exits the
    application.
*/

void LogClient::setup( const String &name )
{
    Endpoint e( Configuration::LogAddress, Configuration::LogPort );
    if ( !e.valid() ) {
        fprintf( stderr,
                 "LogClient: Unable to parse log server address %s:%d\n",
                 Configuration::text( Configuration::LogAddress ).cstr(),
                 Configuration::scalar( Configuration::LogPort ) );
        exit( -1 );
    }

    LogClient *client = new LogClient();
    client->c = new LogClientHelper( Connection::socket( e.protocol() ),
                                     e, client );
    client->c->setBlocking( true );
    if ( client->c->connect( e ) < 0 ) {
        fprintf( stderr, "LogClient: Unable to connect to server %s\n",
                 e.string().cstr() );
        exit( -1 );
    }
    client->c->setBlocking( false );
    client->c->enqueue( "name " + name + "\r\n" );
    Loop::addConnection( client->c );
}
