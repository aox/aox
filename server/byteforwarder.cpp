#include "byteforwarder.h"

#include "arena.h"
#include "scope.h"
#include "buffer.h"


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


/*! \reimp */

void ByteForwarder::react( Event e )
{
    switch( e ) {
    case Read:
        if ( s ) {
            Arena a;
            Scope b( &a );
            Buffer * r = readBuffer();
            s->writeBuffer()->append( *r->string( r->size() ) );
        }
        break;

    case Timeout:
    case Connect:
    case Error:
    case Close:
        setState( Closing );
        s->setState( Closing );
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
