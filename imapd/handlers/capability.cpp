#include "capability.h"

#include <string.h>


/*!  Constructs an empty Capability object. */

Capability::Capability()
    : Command()
{
}


/*! Destroys the object and frees any allocated resources. */

Capability::~Capability()
{
}


/*! Prints the capability response. */

void Capability::execute()
{
    respond( "CAPABILITY IMAP4rev1 LITERAL+ COMPRESS=DEFLATE" );
}
