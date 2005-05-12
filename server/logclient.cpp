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
class LogClientData
    : public Connection
{
public:
    LogClientData( int fd, const Endpoint & e, Logger *client )
        : Connection( fd, Connection::LogClient ),
          logServer( e ), owner( client )
    {
    }

    ~LogClientData()
    {
        Loop::removeConnection( this );
        delete owner;
        owner = 0;
    }

    void reconnect() {
        // XXX: This function is used only to reconnect to the log
        // server in the tlsproxy after fork. It is not generally
        // useful, and the pretence should be removed someday.
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

    Endpoint logServer;
    Logger *owner;
    String name;
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
    d->reconnect();
    d->enqueue( s );
    if ( d->state() == Connection::Connected )
        d->write();
}


/*! Connects to the configured log server and creates a singleton
    Logger named \a n talking to that server.

    If setup() cannot connect to a log server, it brutally exits the
    application.
*/

void LogClient::setup( const String & n )
{
    Endpoint e( Configuration::LogAddress, Configuration::LogPort );
    if ( !e.valid() ) {
        fprintf( stderr,
                 "%s: Unable to parse log server address %s:%d\n",
                 String(n).cstr(),
                 Configuration::text( Configuration::LogAddress ).cstr(),
                 Configuration::scalar( Configuration::LogPort ) );
        exit( -1 );
    }

    LogClient *client = new LogClient();
    client->d = new LogClientData( Connection::socket( e.protocol() ),
                                   e, client );
    client->d->name = n;
    client->d->setBlocking( true );
    if ( client->d->connect( e ) < 0 ) {
        fprintf( stderr, "%s: Unable to connect to server %s\n",
                 client->name().cstr(), e.string().cstr() );
        exit( -1 );
    }
    client->d->setBlocking( false );
    client->d->enqueue( "name " + client->name() + "\r\n" );
    Loop::addConnection( client->d );
}


String LogClient::name() const
{
    return d->name;
}
