#include "imapsession.h"

#include "global.h"
#include "mailbox.h"
#include "event.h"


class SessionData {
public:
    SessionData()
        : readOnly( false ), mailbox( 0 )
    {}

    bool readOnly;
    Mailbox *mailbox;
};


/*! \class ImapSession imapsession.h
    This class contains all data associated with an IMAP session.

    Right now, the only session data is the currently-selected Mailbox.
*/


/*! Creates a new ImapSession for the Mailbox \a m.
    If \a readOnly is true, the session is read-only.
*/

ImapSession::ImapSession( Mailbox *m, bool readOnly )
    : d( new SessionData )
{
    d->mailbox = m;
    d->readOnly = readOnly;
}


/*! Destroys an ImapSession.
*/

ImapSession::~ImapSession()
{
}


/*! Returns a pointer to the currently selected Mailbox, or 0 if there
    isn't one.
*/

Mailbox *ImapSession::mailbox() const
{
    return d->mailbox;
}


/*! Returns the UID of the message with MSN \a msn.
*/

uint ImapSession::uid( uint msn ) const
{
    return 0;
}
