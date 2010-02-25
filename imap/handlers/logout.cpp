// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "logout.h"

#include "imap.h"


/*! \class Logout logout.h
    Terminates an IMAP session (RFC 3501 section 6.1.3)
*/

void Logout::execute()
{
    imap()->endSession();
    respond( "BYE logout" );
    imap()->setState( IMAP::Logout );
    // close the connection after the next event loop iteration
    // instead of at once, to avoid problems with squirrelmail.
    // squirrelmail reacts to the EOF before it has reacted to the
    // prior BYE, if they arrive in the same packet.
    imap()->setTimeoutAfter( 1 );
    finish();
}
