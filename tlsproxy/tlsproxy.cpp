#include "arena.h"
#include "scope.h"
#include "configuration.h"
#include "connection.h"
#include "logclient.h"
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
    {
        Loop::addConnection( this );
    }

    ~TLSProxy()
    {
        Loop::removeConnection( this );
    }

    void react( Event ) {
    }
};


int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Configuration::setup( "/dev/null" );

    Loop::setup();

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    Listener< TLSProxy >::create( "TLS proxy", "127.0.0.1", 2443 );

    Configuration::report();
    l.commit();

    Loop::start();
}
