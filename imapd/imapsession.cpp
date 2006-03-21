// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapsession.h"

#include "imap.h"


class ImapSessionData
    : public Garbage
{
public:
    ImapSessionData(): i( 0 ), annotateUpdates( false ) {}
    class IMAP * i;
    bool annotateUpdates;
};


/*! \class ImapSession imapsession.h
    This class inherits from the Session class, and provides two
    IMAP-specific output functions.
*/

/*! Creates a new ImapSession for the Mailbox \a m to be accessed
    using \a imap. If \a readOnly is true, the session is read-only.
*/

ImapSession::ImapSession( IMAP * imap, Mailbox *m, bool readOnly )
    : Session( m, readOnly ),
      d( new ImapSessionData )
{
    d->i = imap;
}


ImapSession::~ImapSession()
{
}


/*! Returns a pointer to the IMAP connection that's using this session. */

IMAP * ImapSession::imap() const
{
    return d->i;
}


void ImapSession::emitExpunge( uint msn )
{
    d->i->enqueue( "* " + fn( msn ) + " EXPUNGE\r\n" );
}


void ImapSession::emitExists( uint number )
{
    d->i->enqueue( "* " + fn( number ) + " EXISTS\r\n" );
    uint n = uidnext();
    if ( n > announced() ) {
        d->i->enqueue( "* OK [UIDNEXT " + fn( n ) + "] next uid\r\n" );
        setAnnounced( n );
    }
}


/*! Notifies this session whether annotation changes should be
    published. If \a b is true, this session should be notified of
    annotation changes made by others, and if \a b is false, not.  The
    initial value is false.
*/

void ImapSession::setAnnotateUpdates( bool b )
{
    d->annotateUpdates = b;
}


/*! Returns the value set using setAnnotateUpdates(), or false if
    setAnnotateUpdates() has not been called.
*/

bool ImapSession::annotateUpdates() const
{
    return d->annotateUpdates;
}
