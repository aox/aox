#include "arena.h"
#include "scope.h"
#include "configuration.h"
#include "connection.h"
#include "listener.h"
#include "loop.h"
#include "log.h"


/*! \nodoc */

class TLSProxy
    : public Connection
{
public:
    TLSProxy( int fd )
        : Connection( fd, Connection::TLSProxy )
    {}

    void react( Event ) {
    }
};


int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Listener< TLSProxy >::create( "TLS proxy", "127.0.0.1", 2443 );
    Loop::start();
}
