#include "ocserver.h"

#include "list.h"
#include "string.h"
#include "buffer.h"
#include "loop.h"


class OCSData {
public:
};

static List< OCServer > servers;


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
    servers.append( this );
    Loop::addConnection( this );
}


OCServer::~OCServer()
{
    servers.take( servers.find( this ) );
    Loop::removeConnection( this );
}


void OCServer::react( Event e )
{
    switch ( e ) {
    case Read:
        parse();
        break;

    default:
        break;
    }
}


/*! Parses messages from the OCClient. */

void OCServer::parse()
{
    String *s = readBuffer()->removeLine();

    if ( !s )
        return;

    int i = s->find( ' ' );
    String tag = s->mid( 0, i );
    String msg = s->mid( i+1 ).stripCRLF().lower();

    if ( tag == "*" )
        OCServer::send( msg );
}


/*! Sends the message \a s to all connected servers. */

void OCServer::send( const String &s )
{
    String msg = "* " + s + "\n";

    List< OCServer >::Iterator it( servers.first() );
    while ( it ) {
        it->enqueue( msg );
        it->write();
        it++;
    }
}


/*! Returns a pointer to the list of active client connections. */

List< OCServer > *OCServer::connections()
{
    return &servers;
}
