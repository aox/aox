#include "starttls.h"


/*! \class StartTLS starttls.h
    Initiates TLS negotiation (RFC 3501, §6.2.1)
*/


/*! \reimp */

void StartTLS::execute()
{
    error( No, "unimplemented" );
    finish();
}
