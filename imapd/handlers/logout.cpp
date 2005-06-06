// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "logout.h"

#include "imap.h"


/*! \class Logout logout.h
    Terminates an IMAP session (RFC 3501 section 6.1.3)
*/

void Logout::execute()
{
    respond( "BYE" );
    imap()->setState( IMAP::Logout );
    finish();
}
