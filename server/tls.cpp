#include "tls.h"

#include "arena.h"
#include "scope.h"
#include "string.h"
#include "connection.h"
#include "loop.h"
#include "log.h"


static Arena tlsArena;
static class TLSClient *client;


// This is our persistent connection to the TLS proxy.
class TLSClient
    : public Connection
{
public:
    TLSClient( int s )
        : Connection( s, Connection::TLSClient )
    {
        Loop::addConnection( this );
    }

    ~TLSClient() {
        Loop::removeConnection( this );
        client = 0;
    }

    void react( Event ) {
    }
};


/*! \class TLS tls.h
    This class is responsible for talking to the TLS proxy.

    This class connects to the TLS proxy server at startup, and is later
    used to create TLS server and client proxies for other connections.
*/

/*! This function connects to the TLS proxy server.
    It expects to be called by ::main().
*/

void TLS::setup()
{
    Scope x( &tlsArena );
    Endpoint e( "127.0.0.1", 2443 );

    client = new TLSClient( Connection::socket( e.protocol() ) );
    client->setBlocking( true );

    if ( client->connect( e ) < 0 ) {
        log( Log::Disaster, "Unable to connect to TLS proxy " + e + "\n" );
        return;
    }

    client->setBlocking( false );
}
