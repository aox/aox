// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapsession.h"

#include "imap.h"


/*! \class ImapSession imapsession.h
    This class inherits from the Session class, and provides two
    IMAP-specific output functions.
*/

/*! Creates a new ImapSession for the Mailbox \a m to be accessed
    using \a imap. If \a readOnly is true, the session is read-only.
*/

ImapSession::ImapSession( IMAP *imap, Mailbox *m, bool readOnly )
    : Session( m, readOnly ),
      i( imap )
{
}


ImapSession::~ImapSession()
{
}


/*! Returns a pointer to the IMAP connection that's using this session. */

IMAP * ImapSession::imap() const
{
    return i;
}


void ImapSession::emitExpunge( uint msn )
{
    i->enqueue( "* " + fn( msn ) + " EXPUNGE\r\n" );
}


void ImapSession::emitExists( uint number )
{
    i->enqueue( "* " + fn( number ) + " EXISTS\r\n"
                "* OK [UIDNEXT " + fn( uidnext() ) + "]\r\n" );
}
