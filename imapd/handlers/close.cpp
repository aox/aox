#include "close.h"

#include "imap.h"


/*! \class Close

    \brief The Close class implements the IMAP CLOSE command.
    
    Four lines of code and seemingly correct.

    Since Close is a variant of Expunge, this class inherits Expunge
    and switches to authenticated state after a silent expunge.
*/

void Close::execute()
{
    expunge( false );
    imap()->setMailbox( 0 );
    imap()->setState( IMAP::Authenticated );
    setState( Finished );
}
