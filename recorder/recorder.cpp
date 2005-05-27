// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "recorder.h"

#include "file.h"
#include "event.h"
#include "buffer.h"



class RecorderData
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
    uint ls = 0;
    uint i = 0;
    while ( i >= ls ) {
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
    f.append( s->mid( 0, ls ) );
    *s = s->mid( ls );
}


void RecorderData::assertEmpty()
{
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
    d->client = new RecorderClient( d );
}


void RecorderServer::react( Event e )
{
    switch( e ) {
    case Read:
        d->toServer.append( readBuffer()->string( readBuffer()->size() ) );
        if ( d->toServer.find( '\n' ) )
            d->dump( RecorderData::ToClient );
        break;
    case Close:
        d->dump( RecorderData::ToServer );
        d->dump( RecorderData::ToClient );
        d->assertEmpty();
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

RecorderClient::RecorderClient( RecorderServerData * sd )
    : Connection(), d( sd )
{
    connect( RecorderServer::endpoint() );
}


/*!

*/

void RecorderClient::react( Event )
{
    switch( e ) {
    case Read:
        d->toClient.append( readBuffer()->string( readBuffer()->size() ) );
        if ( d->toClient.find( '\n' ) )
            d->dump( RecorderData::ToServer );
        break;
    case Close:
        d->dump( RecorderData::ToServer );
        d->dump( RecorderData::ToClient );
        d->assertEmpty();
        break;
    default:
        {
            // an error of some sort
        }
        break;
    }

}
