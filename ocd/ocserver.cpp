#include "ocserver.h"

#include "list.h"
#include "string.h"
#include "buffer.h"


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
}


/*! \reimp */

void OCServer::react( Event e )
{
    switch ( e ) {
    case Read:
        parse();
        break;

    case Close:
        servers.take( servers.find( this ) );
        break;

    default:
        break;
    }
}


/*! Parses messages from the OCClient. */

void OCServer::parse()
{
}


/*! Distributes the message \a s to all connected servers. */

void OCServer::distribute( const String &s )
{
    List< OCServer >::Iterator it = servers.first();

    while ( it ) {
        it->enqueue( s );
        it->write();
        it++;
    }
}


/*! Returns a pointer to the list of active client connections. */

List< OCServer > *OCServer::connections()
{
    return &servers;
}
