/*! \class Create create.h
    \brief Creates a new mailbox (RFC 3501, §6.3.3)
*/

#include "create.h"

#include "imap.h"

void Create::parse()
{
    m = astring();
    end();
}

void Create::execute()
{
    error( No, "unimplemented command" );
    setState( Finished );
}
