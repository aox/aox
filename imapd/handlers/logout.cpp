#include "logout.h"

#include "../imap.h"


/*!  Constructs an empty

*/

Logout::Logout()
    : Command()
{

}


/*! Destroys the object and frees any allocated resources.

*/

Logout::~Logout()
{
}


/*! Carries out the actual logout. */

void Logout::execute()
{
    imap()->setState( IMAP::Logout );
    setState( Finished );
}
