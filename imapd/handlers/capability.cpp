#include "capability.h"

#include <string.h>


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
/* authentication */ "AUTH=ANONYMOUS AUTH=PLAIN " \
/* draft-gulbrandsen */ "COMPRESS=DEFLATE " \
/* RFC 2177 */ "IDLE " \
/* RFC 2088 - no trailing space */ "LITERAL+"


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
