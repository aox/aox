#include "imapsession.h"

#include "event.h"
#include "mailbox.h"


class SessionData {
public:
    SessionData()
        : loaded( false ), failed( false ), readOnly( false ),
          mailbox( 0 ), handler( 0 )
    {}

    bool loaded;
    bool failed;
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

ImapSession::ImapSession( const String &m, bool readOnly, EventHandler *eh )
    : d( new SessionData )
{
    d->handler = eh;
    d->mailbox = Mailbox::lookup( m );
    d->readOnly = readOnly;

    if ( !d->mailbox ) {
        d->failed = true;
        return;
    }

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


/*! Returns true if this ImapSession could not be successfully started
    (probably because the mailbox does not exist).
*/

bool ImapSession::failed() const
{
    return d->failed;
}


/*! Returns true if this ImapSession has successfully acquired session
    data from the database, or has failed to do so; or false if it is
    still awaiting completion.
*/

bool ImapSession::loaded() const
{
    return d->loaded || d->failed;
}


/*! Returns a pointer to the currently selected Mailbox, or 0 if there
    isn't one.
*/

Mailbox *ImapSession::mailbox() const
{
    return d->mailbox;
}
