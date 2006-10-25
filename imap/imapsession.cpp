// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapsession.h"

#include "imap.h"


class ImapSessionData
    : public Garbage
{
public:
    ImapSessionData(): i( 0 ) {}
    class IMAP * i;
    MessageSet expungedFetched;
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
    d->expungedFetched.clear();
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


/*! Records that \a set was fetched while also expunged. If any
    messages in \a set have already been recorded,
    recordExpungedFetch() summarily closes the IMAP connection.
*/

void ImapSession::recordExpungedFetch( const MessageSet & set )
{
    MessageSet already = set.intersection( d->expungedFetched );
    d->expungedFetched.add( set );
    if ( already.isEmpty() )
        return;

    d->i->enqueue( "* BYE These messages have been expunged: " +
                   set.set() + "\r\n" );
    d->i->setState( IMAP::Logout );
}
