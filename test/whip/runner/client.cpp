#include "client.h"

#include "runner.h"

#include "allocator.h"
#include "buffer.h"
#include "eventloop.h"

#include <stdio.h>


static EString * server;


class TestClientData
    : public Garbage
{
public:
    TestClientData(): r( 0 ) {}
    TestRunner * r;
    EString n;
};


/*! Constructs a test client that will run through \a scripts and then
    disappear. If \a verbose is true, the client dumps input and
    output to stdout even if no errors happen. If it's false, i/o is
    dumped to stderr, and only if an error happens.
*/

TestClient::TestClient( TestRunner * owner, const EString & name,
                        int fd )
    : Connection( fd, Connection::Client ), d( new TestClientData )
{
    d->r = owner;
    d->n = name;
    EventLoop::global()->addConnection( this );
}


/*! Processes server output, timeouts etc. and sends new input to the
    server. \a e is either server information or a 10-second timeout.
*/

void TestClient::react( Event e )
{
    d->r->react( e, this );
    if ( e == Close )
        EventLoop::global()->removeConnection( this );
}


void TestClient::setServerAddress( const EString &s )
{
    server = new EString( s );
    Allocator::addEternal( server, "server address" );
}


/*! Returns this client's name, as specified to the constructor.

*/

EString TestClient::name() const
{
    return d->n;
}


/*! Returns the IP address of the server to be whipped, 127.0.0.1 by
    default. */

EString TestClient::serverAddress()
{
    if ( ::server )
        return *server;
    return "127.0.0.1";
}


/*! Does nothing if the client is Listening; otherwise defers to
    Connection::read().
*/

void TestClient::read()
{
    if ( state() == Listening )
        return;
    Connection::read();
}


/*! Does nothing if the client is Listening; otherwise defers to
    Connection::write().
*/

void TestClient::write()
{
    if ( state() == Listening )
        return;
    Connection::write();
}
