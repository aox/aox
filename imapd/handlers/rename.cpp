#include "rename.h"

#include "mailbox.h"


/*! \class Rename rename.h
    Renames a mailbox (RFC 3501, §6.3.5)
*/


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
