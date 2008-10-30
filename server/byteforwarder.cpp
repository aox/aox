// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "byteforwarder.h"

#include "buffer.h"
#include "log.h"

// struct timeval, fd_set
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
// read, select
#include <unistd.h>


/*! \class ByteForwarder byteforwarder.h
  The ByteForwarder class forwards all it reads to a sibling forwarder.

  In effect, what one ByteForwarder reads, another reads, and what the
  other reads, the first one writes. Perfect for forwarding data
  between two sockets.

  ByteForwarder is used as a helper for TlsServer.
*/

/*! Constructs an empty ByteForwarder on the file descriptor \a s,
    tied to \a c. When this ByteForwarder is closed, it closes \a c,
    too.

    If \a user is true, the ByteForwarder logs as though it is
    conncted to a client/user. If it is false, it logs as though it is
    connected to tlsproxy.
*/

ByteForwarder::ByteForwarder( int s, Connection * c, bool user )
    : Connection( s, Pipe ), s( 0 ), p( c ), u( user )
{
}


void ByteForwarder::react( Event e )
{
    if ( !p )
        return;

    switch( e ) {
    case Read:
        if ( s ) {
            Buffer * r = readBuffer();
            String bytes( r->string( r->size() ) );
            s->writeBuffer()->append( bytes );
            r->remove( bytes.length() );
            if ( u )
                log( "Wrote " + fn( bytes.length() ) + " bytes to tlsproxy",
                     Log::Debug );
            else
                log( "Wrote " + fn( bytes.length() ) + " bytes to " +
                     p->peer().address(), Log::Debug );
            setTimeoutAfter( 3 );
        }
        break;

    case Timeout:
        if ( !s )
            ; // we closed. there's no point in doing anything.
        else if ( u )
            log( "No data received from client for three seconds",
                 Log::Debug );
        else
            log( "No data received from tlsproxy for three seconds",
                 Log::Debug );
        break;

    case Error:
    case Close:
        if ( e == Close ) {
            if ( u ) {
                log( peer().address() + " closed the connection" );
                p->log( "Closing, because " + peer().address() +
                        " closed its connection" );
            }
            else {
                log( "tlsproxy closed the connection" );
                p->log( "Closing connection from " + p->peer().address() +
                        " because tlsproxy closed its connection" );
            }
        }
        else {
            if ( u ) {
                log( peer().address() +
                     ": Unexpected error. Closing connection",
                     Log::Error );
                p->log( "Closing, because tlsproxy closed its connection",
                        Log::Error  );
            }
            else {
                log( "Unexpected error from tlsproxy. Closing connection",
                     Log::Error  );
                p->log( "Closing connection from " + p->peer().address() +
                        " because of a tlsproxy error",
                        Log::Error  );
            }
        }
        close();
        p->close();
        p = 0;
        break;

    case Connect:
    case Shutdown:
        break;
    }
}


/*! Notifies this ByteForwarder (and its old and new siblings) that it
    is to write using \a sibling, or not write at all if \a sibling is
    null.
*/

void ByteForwarder::setSibling( ByteForwarder * sibling )
{
    if ( s == sibling )
        return;

    if ( s )
        s->setSibling( 0 ); // temporarily detach
    s = sibling;
    if ( sibling )
        sibling->setSibling( this );
}
