#include "create.h"

#include "mailbox.h"


/*! \class Create create.h
    Creates a new mailbox (RFC 3501, §6.3.3)
*/


/*! \reimp */

void Create::parse()
{
    space();
    name = astring();
    end();
}


/*! \reimp */

void Create::execute()
{
    error( No, "unimplemented command" );
    setState( Finished );
}
