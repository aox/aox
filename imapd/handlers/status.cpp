#include "status.h"


/*! \class Status status.h
    Returns the status of the specified mailbox (RFC 3501, §6.3.10)
*/


/*! \reimp */

void Status::parse()
{
    end();
}


/*! \reimp */

void Status::execute()
{
    finish();
}
