#include "imapsession.h"

#include "mailbox.h"


class SessionData {
public:
    SessionData()
        : mailbox( 0 )
    {}

    Mailbox *mailbox;
};


/*! \class ImapSession imapsession.h
    This class contains all data associated with an IMAP session.

    Right now, the only session data is the currently-selected Mailbox.
*/


/*! Creates an ImapSession for the Mailbox \a m.
*/

ImapSession::ImapSession( Mailbox *m )
    : d( new SessionData )
{
    d->mailbox = m;
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
