/*! \class Noop noop.h
    \brief NOOP does nothing (RFC 3501, §6.1.2)

    One might surmise that this function is a true noop, but it's not.
    The side effects need to be handled somehow.

    This class is currently serving as a testing ground for the database
    interface. AMS 20040412
*/

#include "noop.h"

// XXX: We should only need to include one header (database) here.
#include "cache.h"
#include "database.h"

#include "string.h"

void Noop::execute()
{
    switch ( st ) {
    case Started:
        q = new Query( "" );
        Database::query( q );
        break;

    case Waiting:
        if ( q->state() == Query::Submitted )
            return;

        while ( q->hasResults() ) {
            // Snarf a single row and respond.
            n++;
        }

        if ( q->state() == Query::Completed ) {
            if ( n == 0 ) {
                // Send an error message.
            }

            setState( Finished );
        }

        break;
    }
}
