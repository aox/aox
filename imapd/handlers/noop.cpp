#include "noop.h"


/*! \class Noop noop.h
    NOOP does nothing (RFC 3501, §6.1.2)

    One might surmise that this function is a true noop, but it's not.
    The side effects need to be handled somehow.
*/

void Noop::execute()
{
    finish();
}



/*! \class Check noop.h
    Performs a checkpoint of the selected mailbox (RFC 3501, §6.4.1)

    This command needs to do nothing in our implementation.
*/

void Check::execute()
{
    finish();
}
