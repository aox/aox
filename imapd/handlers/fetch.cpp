#include "fetch.h"


void Fetch::parse()
{
    
}


/*! One might surmise that this function is a true noop, but it's
    not. The side effects need to be handled somehow.
*/

void Fetch::execute()
{
    // executing a noop is very simple.
    setState( Finished );
}
