/*! \class Create create.h
    Creates a new mailbox (RFC 3501, §6.3.3)
*/

#include "create.h"

#include "imap.h"

void Create::parse()
{
    space();
    m = astring();
    end();
}

void Create::execute()
{
    error( No, "unimplemented command" );
    setState( Finished );
}
