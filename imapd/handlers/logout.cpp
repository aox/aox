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
    // close the connection in a second instead of at once, to avoid
    // problems with squirrelmail. squirrelmail reacts to the EOF
    // before it has reacted to the prior BYE, if they arrive in the
    // same packet.
    imap()->setTimeoutAfter( 1 );
    finish();
}
