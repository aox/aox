#include "imapsession.h"

#include "global.h"
#include "mailbox.h"
#include "event.h"
#include "messageset.h"


class SessionData {
public:
    SessionData()
        : readOnly( false ), mailbox( 0 )
    {}

    bool readOnly;
    Mailbox *mailbox;
    MessageSet messages;
    MessageSet recent;
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


/*! Returns true if this is a read-only session (as created by EXAMINE),
    and false otherwise (SELECT).
*/

bool ImapSession::readOnly() const
{
    return d->readOnly;
}


/*! Returns the UID of the message with MSN \a msn, or 0 if there is
    no such message.
*/

uint ImapSession::uid( uint msn ) const
{
    return d->messages.value( msn );
}


/*! Returns the MSN of the message with UID \a uid, or 0 if there is
    no such message.
*/

uint ImapSession::msn( uint uid ) const
{
    return d->messages.index( uid );
}


/*! Returns the number of messages visible in this session. */

uint ImapSession::count() const
{
    return d->messages.count();
}


/*! Returns a pointer to message \a uid, or a null pointer if there is
    no such message.
*/

Message * ImapSession::message( uint uid ) const
{
    if ( uid )
        ;
    return 0;
}


/*! Returns a MessageSet containing all messages marked "\Recent" in
    this session.
*/

MessageSet ImapSession::recent() const
{
    return d->recent;
}


/*! Returns true only if the message \a uid is marked as "\Recent" in
    this session.
*/

bool ImapSession::isRecent( uint uid ) const
{
    // return d->recent.contains( uid );
    return false;
}


/*! Marks the message \a uid as "\Recent" in this session. */

void ImapSession::addRecent( uint uid )
{
    d->recent.add( uid );
}
