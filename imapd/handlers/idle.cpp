// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
    imap()->enqueue( "+\r\n" );
    imap()->write();
}


/*! Reads the "DONE" line and switches off IDLE mode. */

void Idle::read()
{
    String *s = imap()->readBuffer()->removeLine();
    if ( !s )
        return;
    String r = s->lower();
    if ( r != "done" )
        error( Bad, "Expected DONE, saw: " + r );
    imap()->setIdle( false );
    imap()->reserve( 0 );
    finish();
}
