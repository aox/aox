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


/*! Creates an empty ImapSession.
*/

ImapSession::ImapSession()
    : d( new SessionData )
{
}


/*! Returns a pointer to the Mailbox currently selected in this session,
    or 0 if there isn't one.
*/

Mailbox *ImapSession::mailbox() const
{
    return d->mailbox;
}


/*! Sets this session's Mailbox to \a m. */

void ImapSession::setMailbox( Mailbox *m )
{
    d->mailbox = m;
}
