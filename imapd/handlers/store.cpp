/*! \class Store store.h
    \brief STORE (RFC 3501, §6.4.6)
*/

#include "store.h"


void Store::execute()
{
    setState( Finished );
}
