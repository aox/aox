#include "capability.h"

#include "imap.h"


#define BASECAPS "IMAP4rev1 LITERAL+ IDLE ID NAMESPACE UNSELECT LISTEXT " \
                 "SASL-IR AUTH=ANONYMOUS AUTH=CRAM-MD5 AUTH=DIGEST-MD5"

#define CAPS BASECAPS " LOGINDISABLED STARTTLS"
#define TLSCAPS BASECAPS " AUTH=PLAIN"


/*! \class Capability capability.h
    Announces supported features (RFC 3501, §6.1.1)

    We announce the following capabilities:

    RFC 3501: IMAP4rev1, LOGINDISABLED, STARTTLS.
    RFC 2088: LITERAL+
    RFC 2177: IDLE
    RFC 2971: ID
    RFC 2342: NAMESPACE
    RFC 3691: UNSELECT
    draft-ietf-imapext-list-extensions: LISTEXT
    draft-siemborski-imap-sasl-initial-response: SASL-IR
    RFC 2245: AUTH=ANONYMOUS
    RFC 2595: AUTH=PLAIN
    RFC 2195: AUTH=CRAM-MD5
    RFC 2831: AUTH=DIGEST-MD5
*/

/*! \reimp */

void Capability::execute()
{
    if ( imap()->hasTLS() )
        respond( "CAPABILITY " TLSCAPS );
    else
        respond( "CAPABILITY " CAPS );
    finish();
}


/*! This static function returns the capabilities applicable before TLS
    has been negotiated.
*/

const char * Capability::capabilities()
{
    return CAPS;
}
