// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "logout.h"

#include "imap.h"


/*! \class Logout logout.h
    Terminates an IMAP session (RFC 3501 section 6.1.3)
*/

void Logout::execute()
{
    respond( "BYE logout" );
    imap()->setState( IMAP::Logout );
    // close the connection in five seconds instead of at once, to
    // avoid problems with squirrelmail. squirrelmail detects the EOF
    // before it has parsed the prior BYE.
    imap()->setTimeoutAfter( 5 );
    finish();
}
