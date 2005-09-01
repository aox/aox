// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "ocadmin.h"

#include "string.h"
#include "buffer.h"
#include "ocserver.h"
#include "eventloop.h"


class OCAData
    : public Garbage
{
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
    EventLoop::global()->addConnection( this );
    enqueue( "Hi. This is Oryx OCAdmin " +
             Configuration::compiledIn( Configuration::Version ) + "\r\n" );
}


void OCAdmin::react( Event e )
{
    switch ( e ) {
    case Read:
        parse();
        break;

    default:
        break;
    }
    commit();
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
        List< OCServer >::Iterator it( servers );
        while ( it ) {
            // this doens't look terribly useful. shouldn't we say
            // something about the servers?
            enqueue( it->peer().string() + "\r\n" );
            ++it;
        }
    }
    else if ( r == "shutdown" ) {
        OCServer::send( "shutdown\r\n" );
        enqueue( "Shutting down\r\n" );
        EventLoop::global()->shutdown();
    }
    else if ( r == "quit" || r == "exit" ) {
        setState( Closing );
        enqueue( "Closing connection\r\n" );
    }
    else {
        enqueue( "Valid commands: shutdown, ls, quit.\r\n" );
    }
}
