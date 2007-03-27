// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "ocserver.h"

#include "list.h"
#include "string.h"
#include "buffer.h"
#include "eventloop.h"
#include "allocator.h"


class OCSData
    : public Garbage
{
public:
};

static List< OCServer > * servers;


/*! \class OCServer ocserver.h
    This class coordinates between a cluster of IMAP servers.

    Every IMAP server initiates a connection to the cluster coordination
    server at startup. The server distributes administrative messages to
    each participant in the cluster.
*/


/*! Creates an OCServer for the fd \a s. */

OCServer::OCServer( int s )
    : Connection( s, Connection::OryxServer ), d( new OCSData )
{
    if ( !servers ) {
        servers = new List<OCServer>;
        Allocator::addEternal( servers, "list of OCServer objects" );
    }
    servers->append( this );
    EventLoop::global()->addConnection( this );
}


void OCServer::react( Event e )
{
    switch ( e ) {
    case Read:
        parse();
        break;

    case Error:
    case Close:
        if ( servers )
            servers->take( servers->find( this ) );
        EventLoop::global()->removeConnection( this );
        break;

    default:
        break;
    }
}


/*! Parses messages from the OCClient. */

void OCServer::parse()
{
    String *s = readBuffer()->removeLine();
    while ( s ) {
        int i = s->find( ' ' );
        String tag = s->mid( 0, i );
        String msg = s->mid( i+1 ).stripCRLF();

        if ( tag == "*" )
            OCServer::send( msg, this );
        s = readBuffer()->removeLine();
    };
}


/*! Sends the message \a s to all connected servers, with one \a
    exception.
*/

void OCServer::send( const String &s, OCServer * exception )
{
    if ( !servers )
        return;

    String msg = "* " + s + "\n";

    List< OCServer >::Iterator it( servers );
    while ( it ) {
        if ( it != exception )
            it->enqueue( msg );
        ++it;
    }
}


/*! Returns a pointer to the list of active client connections. */

List< OCServer > * OCServer::connections()
{
    return servers;
}
