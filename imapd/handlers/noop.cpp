#include "noop.h"


/*!  Constructs a Noop handler */

Noop::Noop()
    : Command()
{
}


/*! Destroys the handler. */

Noop::~Noop()
{
}


/*! One might surmise that this function is a true noop, but it's
  not. The side effects need to be handled somehow.
*/

void Noop::execute()
{
    // executing a noop is very simple.
}
