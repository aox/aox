#include "ocadmin.h"

#include "string.h"
#include "buffer.h"
#include "ocserver.h"
#include "loop.h"


class OCAData {
public:
};


/*! \class OCAdmin ocadmin.h
    Oryx Cluster Administration server.

    This server reads administrative commands, and uses OCServer to send
    them to each participating server in the cluster.
*/


/*! Creates an OCAdmin object for the fd \a s. */

OCAdmin::OCAdmin( int s )
    : Connection( s, Connection::OryxConsole ), d( new OCAData )
{
    Loop::addConnection( this );
}


/*! \reimp */

OCAdmin::~OCAdmin()
{
    Loop::removeConnection( this );
}


/*! \reimp */

void OCAdmin::react( Event e )
{
    switch ( e ) {
    case Read:
        parse();
        break;

    default:
        break;
    }
}


/*! Parses administrative commands. */

void OCAdmin::parse()
{
    String *s = readBuffer()->removeLine();

    if ( !s )
        return;

    String r = s->lower();

    if ( r == "ls" ) {
        List< OCServer > *servers = OCServer::connections();
        List< OCServer >::Iterator it = servers->first();
        while ( it ) {
            enqueue( it->peer().string() + "\r\n" );
            it++;
        }
    }
    else if ( r == "shutdown" ) {
        OCServer::send( "shutdown\r\n" );
    }
    else if ( r == "quit" || r == "exit" ) {
        setState( Closing );
    }
    else {
        enqueue( "?\r\n" );
    }
}
