#include "idle.h"

#include "imap.h"
#include "buffer.h"


/*! \class Idle idle.h
    Implements the RFC 2177 IDLE extension.

    The IDLE extension permits IMAP clients to remain idle, while the
    IMAP server may send EXPUNGE, EXISTS and flag updates at any time.

    This implementation differs from that implied by the RFC in that
    +/DONE is not actually part of the command; Idle prints the +
    itself and waits for DONE during command execution. Thus, "parse
    errors" are not done in parse().
*/


/*! Switches to IDLE mode and grabs the input, such that the DONE can
    be properly processed.
*/

void Idle::execute()
{
    // if we're already finished, or if we've already enabled idle and
    // printed the +, just quit.
    if ( state() == Finished || imap()->idle() )
        return;

    imap()->reserve( this );
    imap()->setIdle( true );
    imap()->writeBuffer()->append( "+\r\n" );
}


/*! Reads the "DONE" line and switches off IDLE mode. */

void Idle::read()
{
    Buffer * b = imap()->readBuffer();

    uint i = 0;
    while ( i < b->size() && (*b)[i] != 10 )
        i++;
    if ( (*b)[i] == 10 ) {
        i++;
        String r( b->string( i )->simplified() );
        b->remove( i );
        // if we get something other than done, we must respond with
        // an error, but that's all, isn't it? we don't need to
        // actually do anything. either way, the idleness is over.
        if ( r.lower() != "done" )
            error( Bad, "Expected DONE, saw: " + r );
        imap()->setIdle( false );
        imap()->reserve( 0 );
        setState( Finished );
    }
}
