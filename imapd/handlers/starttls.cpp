#include "starttls.h"

#include "tls.h"
#include "imap.h"
#include "capability.h"


/*! \class StartTLS starttls.h
    Initiates TLS negotiation (RFC 3501, §6.2.1)
*/

/*! \reimp */

void StartTLS::execute()
{
    if ( imap()->hasTLS() ) {
        error( Bad, "Nested STARTTLS" );
        finish();
        return;
    }

    imap()->startTLS();
    finish();
}
