#include "imapsession.h"

#include "mailbox.h"


class SessionData {
public:
    SessionData()
        : mailbox( 0 ), readOnly( false )
    {}

    Mailbox *mailbox;
    bool readOnly;
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
