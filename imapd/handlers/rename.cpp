/*! \class Rename rename.h
    Renames a mailbox (RFC 3501, §6.3.5)
*/

#include "rename.h"

#include "imap.h"

void Rename::parse()
{
    space();
    a = astring();
    space();
    b = astring();
    end();
}

void Rename::execute()
{
    error( No, "unimplemented command" );
    setState( Finished );
}
