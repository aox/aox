#include "namespace.h"


/*! \class Namespace namespace.h
    Implements the NAMESPACE extension specified in RFC 2342.
*/


/*! \reimp */

void Namespace::execute()
{
    respond( "NAMESPACE NIL NIL NIL" );
    finish();
}
