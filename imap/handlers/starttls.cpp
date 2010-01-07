// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "starttls.h"

#if defined(USE_CRYPTLIB)
#include "tls.h"
#endif
#include "imap.h"
#include "capability.h"


/*! \class StartTLS starttls.h

    Initiates TLS negotiation (RFC 3501 section 6.2.1)
*/


/*! Constructs a regular StartTLS parser. */

StartTLS::StartTLS()
    : tlsServer( 0 )
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

#if defined(USE_CRYPTLIB)    
    if ( !tlsServer )
        tlsServer = new TlsServer( this, imap()->peer(), "IMAP" );

    if ( !tlsServer->done() )
        return;

    if ( !tlsServer->ok() ) {
        error( No, "Internal error starting TLS engine" );
        return;
    }
#endif

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
    imap()->startTls( tlsServer );
}
