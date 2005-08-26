// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "idle.h"

#include "imap.h"
#include "buffer.h"
#include "mailbox.h"
#include "imapsession.h"


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
    // find the mailbox we're looking at, if any
    Mailbox * m = 0;
    if ( imap()->session() )
        m = imap()->session()->mailbox();

    log( "idle: " + fn( idling ) + " " + ( m ? m->name() : String("NO MAILBOX") ) );
    // if we're already idling, emit possible reponses and
    if ( idling && m )
        imap()->session()->emitResponses();

    // if the connection went away while we were idling, finish off.
    if ( m && imap()->Connection::state() != Connection::Connected )
        read();

    if ( idling )
        return;

    // if we have to set up idling, do it
    if ( m )
        m->addWatcher( this );

    imap()->reserve( this );
    imap()->enqueue( "+ idling\r\n" );
    imap()->write();
    idling = true;
}


/*! Reads the "DONE" line and switches off IDLE mode. */

void Idle::read()
{
    if ( imap()->Connection::state() != Connection::Connected ) {
        error( Bad, "Leaving idle mode due to connection state change" );
        imap()->reserve( 0 );
        return;
    }

    String * s = 0;
    if ( imap()->Connection::state() == Connection::Connected ) {
        s = imap()->readBuffer()->removeLine();
        if ( !s )
            return;

        String r = s->lower();
        if ( r != "done" )
            error( Bad, "Leaving idle mode due to syntax error: " + r );
    }

    imap()->reserve( 0 );

    Mailbox * m = 0;
    if ( imap()->session() )
        m = imap()->session()->mailbox();
    if ( m )
        m->removeWatcher( this );

    finish();
}
