// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "starttls.h"

#include "tls.h"
#include "imap.h"
#include "capability.h"
#include "tls.h"


/*! \class StartTLS starttls.h

    Initiates TLS negotiation (RFC 3501, §6.2.1)
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
    imap()->reserve( this );
}

void StartTLS::execute()
{
    if ( imap()->hasTls() ) {
        imap()->reserve( 0 );
        error( Bad, "Nested STARTTLS" );
        finish();
        return;
    }

    if ( !tlsServer )
        tlsServer = new TlsServer( this, imap()->peer(), "IMAP" );

    if ( !tlsServer->done() )
        return;

    imap()->reserve( 0 );

    if ( !tlsServer->ok() ) {
        error( No, "Internal error starting TLS engine" );
        return;
    }

    finish();
    imap()->startTls( tlsServer );
}
