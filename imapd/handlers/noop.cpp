/*! \class Noop noop.h
    \brief NOOP does nothing (RFC 3501, §6.1.2)

    One might surmise that this function is a true noop, but it's not.
    The side effects need to be handled somehow.
*/

#include "noop.h"

// XXX: We should only need to include one header (database) here.
#include "cache.h"
#include "database.h"

#include "string.h"

void Noop::execute()
{
    // This is just for testing. AMS 20040318
    Query *q = new Query( "" );
    Database::query( q );

    setState( Finished );
}
