/*! \class Subscribe subscribe.h
    \brief Adds a mailbox to the subscription list (RFC 3501, §6.3.6)
*/

#include "subscribe.h"

#include "imap.h"

void Subscribe::parse()
{
    space();
    m = astring();
    end();
}

void Subscribe::execute()
{
    error( No, "unimplemented command" );
    setState( Finished );
}
