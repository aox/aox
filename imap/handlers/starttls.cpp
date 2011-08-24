// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "starttls.h"

#include "imap.h"
#include "capability.h"


/*! \class StartTLS starttls.h

    Initiates TLS negotiation (RFC 3501 section 6.2.1)
*/


/*! Constructs a regular StartTLS parser. */

StartTLS::StartTLS()
{
}


/*! This implementation hacks to ensure that no other command can be
    parsed meanwhile.
*/

void StartTLS::parse()
{
    end();
    imap()->reserve( this ); // is this necessary any more?
}

void StartTLS::execute()
{
    if ( state() != Executing )
        return;

    if ( imap()->hasTls() ) {
        imap()->reserve( 0 );
        error( Bad, "Nested STARTTLS" );
        finish();
        return;
    }

    finish();
}


/*! This reimplementation starts TLS negotiation just after OK is
    sent.
*/

void StartTLS::emitResponses()
{
    if ( state() == Retired )
        return;
    Command::emitResponses();
    if ( state() != Retired )
        return;
    imap()->startTls();
}
