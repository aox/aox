#include "logout.h"

#include "imap.h"


/*! \class Logout logout.h
    Terminates an IMAP session (RFC 3501, §6.1.3)
*/

/*! \reimp */

void Logout::execute()
{
    respond( "BYE" );
    imap()->setState( IMAP::Logout );
    finish();
}
