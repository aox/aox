/*! \class Logout logout.h
    \brief Terminates an IMAP session (RFC 3501, §6.1.3)
*/

#include "logout.h"

#include "imap.h"


/*! Constructs an empty Logout command. */

Logout::Logout()
    : Command()
{

}


/*! Destroys the object and frees any allocated resources. */

Logout::~Logout()
{
}


/*! Carries out the actual logout. */

void Logout::execute()
{
    respond( "BYE" );
    imap()->setState( IMAP::Logout );
    setState( Finished );
}
