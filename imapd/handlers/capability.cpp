/*! \class Capability capability.h
    Announces supported features (RFC 3501, §6.1.1)
*/

#include "capability.h"


/*! Constructs an empty Capability object. */

Capability::Capability()
    : Command()
{
}


/*! Destroys the object and frees any allocated resources. */

Capability::~Capability()
{
}


// how very evil. this macro thing is used to return the same
// capabilities in two forms, concatenating the strings at compile
// time.
#define CAPA \
/* base */ "IMAP4rev1 " \
/* RFC 2245 */ "AUTH=ANONYMOUS " \
/* RFC 2595 */ "AUTH=PLAIN " \
/* RFC 2195 */ "AUTH=CRAM-MD5 " \
/* RFC 2831 */ /* "AUTH=DIGEST-MD5 " */ \
/* draft-siemborski-imap-sasl-initial-response */ "SASL-IR " \
/* RFC 2177 */ "IDLE " \
/* RFC 2971 */ "ID " \
/* RFC 3691 */ "UNSELECT " \
/* RFC 2088 - no trailing space */ "LITERAL+"
// add nothing after LITERAL+
// everything should be before, and have a trailing space


/*! Prints the capability response. */

void Capability::execute()
{
    respond( "CAPABILITY " CAPA );
    setState( Finished );
}


/*! This static function returns the capabilities, suitable for use in
    a capability response or in a capability response code.
*/

const char * Capability::capabilities()
{
    return CAPA;
}
