// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "recorder.h"

#include "file.h"
#include "event.h"
#include "scope.h"
#include "buffer.h"
#include "listener.h"
#include "resolver.h"
#include "allocator.h"
#include "logclient.h"

#include <stdio.h> // fprintf, printf
#include <stdlib.h> // exit


class RecorderData
    : public Garbage
{
public:
    RecorderData()
        : client( 0 ), server( 0 ), log( 0 )
    {}
    RecorderClient * client;
    RecorderServer * server;
    File * log;
    String toServer;
    String toClient;

    enum Direction { ToServer, ToClient };
    void dump( Direction );
    void assertEmpty();
};


void RecorderData::dump( Direction dir )
{
    String * s = &toServer;
    if ( dir == ToClient )
        s = &toClient;
    uint lines = 0;
    int ls = 0;
    int i = 0;
    while ( i >= 0 ) {
        i = s->find( '\n', ls );
        if ( i >= ls ) {
            lines++;
            ls = i + 1;
        }
    }
    if ( !lines )
        return;
    String f;
    if ( dir == ToClient )
        f.append( "receive " );
    else
        f.append( "send " );
    f.append( fn( lines ) );
    f.append( "\n" );
    i = 0;
    while ( i < ls ) {
        if ( (*s)[i] == 13 && (*s)[i+1] == 10 )
            ; // don't write the CR
        else
            f.append( (*s)[i] );
        i++;
    }
    log->write( f );
    *s = s->mid( ls );
}


void RecorderData::assertEmpty()
{
    log->write( "end\n" );
    if ( !toServer.isEmpty() ) {
        String f;
        f.append( "# The following " );
        f.append( fn( toServer.length() ) );
        f.append( " bytes were sent by the client after the last LF: " );
        f.append( toServer );
        f.append( "\n" );
        log->write( f );
    }
    if ( !toClient.isEmpty() ) {
        String f;
        f.append( "# The following " );
        f.append( fn( toClient.length() ) );
        f.append( " bytes were sent by the server after the last LF: " );
        f.append( toClient );
        f.append( "\n" );
        log->write( f );
    }
}


static String * base = 0;


/*! \class RecorderServer recorder.h

    The RecorderServer class provides the client-facing side of a man
    in the middle that records the TCP stream in a format suitable for
    reporting to Oryx.

    Oryx has debug/test tools that accept approximately this format.
*/


/*! Constructs an RecorderServer answering on socket \a fd, forwarding
    any received data to endpoint() and returning the answers.
*/

RecorderServer::RecorderServer( int fd )
    : Connection( fd, Connection::RecorderServer ),
      d( new RecorderData )
{
    d->server = this;
    d->client = new ::RecorderClient( d );
    d->log = new File( *::base + "." + peer().string(),
                       File::Append, 0644 );
    EventLoop::global()->addConnection( this );

    printf( "New recorder writing %s\n", d->log->name().cstr() );
}


void RecorderServer::react( Event e )
{
    String tmp;
    switch( e ) {
    case Read:
        tmp = readBuffer()->string( readBuffer()->size() );
        d->toServer.append( tmp );
        d->client->enqueue( tmp );
        readBuffer()->remove( tmp.length() );
        if ( d->toServer.find( '\n' ) )
            d->dump( RecorderData::ToClient );
        break;
    case Close:
        d->dump( RecorderData::ToServer );
        d->dump( RecorderData::ToClient );
        d->assertEmpty();
        d->client->close();
        printf( "Closed %s\n", d->log->name().cstr() );
        delete d->log;
        d->log = 0;
        break;
    default:
        {
            // an error of some sort
        }
        break;
    }
}


/*! Constructs a client connection to \a ep, forwarding data using the
    server \a s. This acts as the client portion of a
    man-in-the-middle, and \a s acts as the server portion.
*/

RecorderClient::RecorderClient( RecorderData * sd )
    : Connection(), d( sd )
{
    connect( RecorderServer::endpoint() );
    EventLoop::global()->addConnection( this );
}


void RecorderClient::react( Event e )
{
    String tmp;
    switch( e ) {
    case Read:
        tmp = readBuffer()->string( readBuffer()->size() );
        d->toClient.append( tmp );
        d->server->enqueue( tmp );
        readBuffer()->remove( tmp.length() );
        if ( d->toClient.find( '\n' ) )
            d->dump( RecorderData::ToServer );
        break;
    case Close:
        d->dump( RecorderData::ToServer );
        d->dump( RecorderData::ToClient );
        d->assertEmpty();
        d->server->close();
        delete d->log;
        d->log = 0;
        break;
    default:
        {
            // an error of some sort
        }
        break;
    }

}


static Endpoint * ep;


int main( int argc, char ** argv )
{
    Scope global;
    EventLoop::setup();

    const char * error = 0;
    bool ok = true;
    if ( argc != 5 ) {
        error = "Wrong number of arguments";
        ok = false;
    }

    uint port;
    if ( ok ) {
        port = String( argv[1] ).number( &ok );
        if ( !ok )
            error = "Could not parse own port number";
    }
    if ( ok ) {
        Listener<RecorderServer> * l4
            = new Listener<RecorderServer>( Endpoint( "0.0.0.0", port ),
                                            "recording relay/4", true );
        Allocator::addEternal( l4, "recording listener" );
        Listener<RecorderServer> * l6
            = new Listener<RecorderServer>( Endpoint( "::", port ),
                                            "recording relay/6", true );
        Allocator::addEternal( l6, "recording listener" );

        if ( l4->state() != Connection::Listening &&
             l6->state() != Connection::Listening )
            error = "Could not listen for connections";
    }

    if ( ok ) {
        port = String( argv[3] ).number( &ok );
        if ( !ok )
            error = "Could not parse server's port number";
    }

    if ( ok ) {
        StringList l = Resolver::resolve( argv[2] );
        if ( l.isEmpty() ) {
            ok = false;
            error = (String("Cannot resolve ") + argv[2]).cstr();
        }
        else {
            ep = new Endpoint( *l.first(), port );
            Allocator::addEternal( ep, "target server endpoint" );
        }
        if ( ep && !ep->valid() ) {
            ok = false;
            error = "Invalid server address";
        }
    }

    if ( !ok ) {
        fprintf( stderr,
                 "Error: %s\n"
                 "Usage: recorder port address port filebase\n"
                 "       First port: The recorder's own port.\n"
                 "       Address: The IP address of the server to forward to.\n"
                 "       Second port: The server port to forward to.\n"
                 "       Filebase: The filename base (.<blah> is added).\n",
                 error );
        exit( 1 );
    }

    ::base = new String( argv[4] );
    Allocator::addEternal( ::base, "base of recorded file names" );

    global.setLog( new Log( Log::General ) );
    EventLoop::global()->start();
}


/*! Returns the endpoint to which RecorderClient should connect. */

Endpoint RecorderServer::endpoint()
{
    return *ep;
}
