/*! \class Noop noop.h
    NOOP does nothing (RFC 3501, §6.1.2)

    One might surmise that this function is a true noop, but it's not.
    The side effects need to be handled somehow.
*/


#include "noop.h"


/*! \reimp */

void Noop::execute()
{
    setState( Finished );
}
