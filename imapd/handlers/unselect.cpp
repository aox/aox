/*! \class Unselect unselect.h
    \brief The Unselect class implements the IMAP UNSELECT extension.

    The extension (specified in RFC 3691) is extremely simple: It adds
    the single command "unselect" to change from Selected to
    Authenticated state. Unlike Close, Unselect does not expunge.
*/

#include "unselect.h"

#include "imap.h"


void Unselect::execute()
{
    imap()->setMailbox( 0 );
    imap()->setState( IMAP::Authenticated );
    setState( Finished );
}
