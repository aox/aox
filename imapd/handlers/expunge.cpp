#include "expunge.h"

#include "imap.h"

void Expunge::execute()
{
    expunge( true );
    setState( Finished );
}


/*! This function expunges the current mailbox, emitting suitable
    responses if \a chat is true.
*/

void Expunge::expunge( bool chat )
{
    // as a temporary hack, we emit an error but only if we're
    // supposed to talk.
    if ( chat )
        error( No, "unimplemented command" );
}
