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
    imap()->startTLS();
    finish();
}
