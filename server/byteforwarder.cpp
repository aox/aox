// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "byteforwarder.h"

#include "buffer.h"
#include "log.h"


/*! \class ByteForwarder byteforwarder.h
  The ByteForwarder class forwards all it reads to a sibling forwarder.

  In effect, what one ByteForwarder reads, another reads, and what the
  other reads, the first one writes. Perfect for forwarding data
  between two sockets.

  ByteForwarder is used as a helper for TlsServer.
*/

/*!  Constructs an empty

*/

ByteForwarder::ByteForwarder( int s )
    : Connection( s, Pipe ), s( 0 )
{
}


void ByteForwarder::react( Event e )
{
    switch( e ) {
    case Read:
        if ( s ) {
            Buffer * r = readBuffer();
            String bytes = *r->string( r->size() );
            s->writeBuffer()->append( bytes );
            r->remove( bytes.length() );
        }
        break;

    case Timeout:
    case Connect:
    case Error:
    case Close:
        log( String("Shutting down byte forwarder due to ") +
             ( e == Close ? "peer close." : "error." ) );
        setState( Closing );
        s->close();
        break;

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
