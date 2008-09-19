// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapresponse.h"

#include "imapsession.h"
#include "imap.h"



class ImapResponseData
    : public Garbage
{
public:
    ImapResponseData()
        : session( 0 ), imap( 0 ),
          sent( false ), cmsn( false )
        {}

    Session * session;
    IMAP * imap;
    String text;
    bool sent;
    bool cmsn;
};


/*! \class ImapResponse imapresponse.h

    The ImapResponse class models a single IMAP response. It has the
    knowledge necessary to decide whether a particular response can be
    sent, has been sent, and formulates the exact textual form of the
    response.
*/



/*! Constructs a response which is bound to \a session and sends the
    constant string \a response. \a response should not contain the
    leading "* " or trailing CRLF.

    The response is meaningful() only if \a session is active, and
    changesMsn() returns false.
*/

ImapResponse::ImapResponse( ImapSession * session, const String & response )
    : Garbage(), d( new ImapResponseData )
{
    d->session = session;
    d->imap = session->imap();
    d->text = response;
    d->imap->respond( this );
}


/*! Constructs a response which is bound to \a session. A subclass is
    responsible for text().

    The response is meaningful() only if \a session is active.
*/

ImapResponse::ImapResponse( ImapSession * session )
    : Garbage(), d( new ImapResponseData )
{
    d->session = session;
    d->imap = session->imap();
    d->imap->respond( this );
}


/*! Constructs a response which is bound to \a server but not to any
    Session, and sends the constant string \a response. \a response
    should not contain the leading "* " or trailing CRLF.

    The response is always meaningful(). changesMsn() returns false.
*/

ImapResponse::ImapResponse( IMAP * server, const String & response )
    : Garbage(), d( new ImapResponseData )
{
    d->imap = server;
    d->text = response;
    d->imap->respond( this );
}


/*! Constructs a response which is bound to \a server but not to any
    Session. The text() must be computed by a subclass.

    The response is always meaningful(). changesMsn() returns false.
*/

ImapResponse::ImapResponse( IMAP * server )
    : Garbage(), d( new ImapResponseData )
{
    d->imap = server;
    d->imap->respond( this );
}


/*! Returns true if setSent() has been called.

*/

bool ImapResponse::sent() const
{
    return d->sent;
}


/*! Notifies this ImapResponse that it has been sent to the client.

    This function is virtual and not const. Subclasses may perform
    state changes in this function, e.g. calling IMAP::endSession(),
    so that the server's state matches what the IMAP client will have
    after parsing this response.
*/

void ImapResponse::setSent()
{
    d->sent = true;
}


/*! Returns the text of the response.

    Subclasses may need to compute this, so if possible it should be
    called only once. The function is const, so subclasses should not
    perform any state changes here (but rather in setSent()).

    If text() returns an empty string, the caller should discard the
    response and not send it.
*/

String ImapResponse::text() const
{
    return d->text;
}


/*! Returns true if this response has meaning, and false if it may be
    discarded.

    One reason to discard a response is that it's related to a
    session, but the session has ended.
*/

bool ImapResponse::meaningful() const
{
    if ( !d->session )
        return true;
    if ( d->imap->session() != d->session )
        return false;
    return true;
}


/*! Returns true if sending this response will change the session()
    MSN map, and false if not.
*/

bool ImapResponse::changesMsn() const
{
    return d->cmsn;
}


/*! Records that when the text() is sent, the client's idea of
    MSN->UID mapping will change.

    Meant to be called by subclass constructors.
*/

void ImapResponse::setChangesMsn()
{
    d->cmsn = true;
}


/*! Returns the session passed to the constructor, or 0 if none. */

Session * ImapResponse::session() const
{
    return d->session;
}


/*! Returns the IMAP server to which this response pertains. */

IMAP * ImapResponse::imap() const
{
    return d->imap;
}


/*! \class ImapByeResponse imapresponse.h

    The ImapByeResponse models a BYE response. Its only responsibility
    is to change the server state commensurately in setSent().
*/


/*! Constructs a BYE response for \a server with resp-text \a
    text. The \a text may include a resp-text-code.
*/

ImapByeResponse::ImapByeResponse( IMAP * server, const String & text )
    : ImapResponse( server, text )
{
}


/*! Returns true if it's still possible to log the client out, and
    false if the deed has somehow been done.
*/

bool ImapByeResponse::meaningful() const
{
    if ( imap()->state() == IMAP::Logout )
        return false;
    if ( imap()->Connection::state() == Connection::Closing )
        return false;
    if ( imap()->Connection::state() == Connection::Inactive )
        return false;
    return true;
}


void ImapByeResponse::setSent()
{
    if ( imap()->session() )
        imap()->endSession();
    imap()->setState( IMAP::Logout );
}
