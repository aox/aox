#include "imapsession.h"

#include "global.h"
#include "mailbox.h"
#include "event.h"


class SessionData {
public:
    SessionData()
        : loaded( false ), readOnly( false ),
          mailbox( 0 ), handler( 0 )
    {}

    bool loaded;
    bool readOnly;
    Mailbox *mailbox;
    EventHandler *handler;
};


/*! \class ImapSession imapsession.h
    This class contains all data associated with an IMAP session.

    Right now, the only session data is the currently-selected Mailbox.
*/


/*! Creates a new ImapSession for the Mailbox \a m.
    If \a readOnly is true, the session is read-only.
    The handler \a eh is notified of completion.
*/

ImapSession::ImapSession( Mailbox *m, bool readOnly, EventHandler *eh )
    : d( new SessionData )
{
    d->mailbox = m;
    d->handler = eh;
    d->readOnly = readOnly;

    begin();
}


/*! Destroys an ImapSession.
*/

ImapSession::~ImapSession()
{
    end();
}


/*! Acquires whatever resources are needed to start a new session.
*/

void ImapSession::begin()
{
    d->loaded = true;
}


/*! Does whatever is needed to end a session.
*/

void ImapSession::end()
{
}


/*! Returns true if this ImapSession has successfully acquired session
    data from the database, or has failed to do so; or false if it is
    still awaiting completion.
*/

bool ImapSession::loaded() const
{
    return d->loaded;
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
