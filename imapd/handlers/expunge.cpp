#include "expunge.h"

#include "imap.h"

/*! \class Expunge expunge.h

  This IMAP command handler is responsible for permanently removeing
  "\deleted" messages.

  It implements EXPUNGE, as specified in RFC 3501 section 6.4.3, and
  helps Close.
*/


void Expunge::execute()
{
    expunge( true );
    setState( Finished );
}


/*! This function expunges the current mailbox, emitting EXPUNGE
    responses if \a chat is true and being silent if \a chat is false.
*/

void Expunge::expunge( bool chat )
{
    // as a temporary hack, we emit an error but only if we're
    // supposed to talk.
    if ( chat )
        error( No, "unimplemented command" );
}
