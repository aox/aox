#include "tls.h"

#include "arena.h"
#include "scope.h"
#include "string.h"
#include "connection.h"
#include "loop.h"

// exit
#include <stdlib.h>
// *printf, stderr
#include <stdio.h>


static Arena tlsArena;
static class TLSClient *client = 0;


// This is our persistent connection to the TLS proxy.
class TLSClient
    : public Connection
{
public:
    TLSClient( int s )
        : Connection( s )
    {}

    ~TLSClient() {
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
*/

void TLS::setup()
{
    Scope x( &tlsArena );
    Endpoint e( "127.0.0.1", 2443 );

    client = new TLSClient( Connection::socket( e.protocol() ) );
    client->setBlocking( true );

    if ( client->connect( e ) < 0 ) {
        fprintf( stderr, "TLSClient: Unable to connect to TLS proxy %s\n",
                 String(e).cstr() );
        perror( "TLSClient: connect() returned" );
        exit( -1 );
    }

    client->setBlocking( false );
    Loop::addConnection( client );
}
