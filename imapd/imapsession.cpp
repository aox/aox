// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapsession.h"

#include "transaction.h"
#include "messageset.h"
#include "mailbox.h"
#include "message.h"
#include "global.h"
#include "event.h"
#include "query.h"
#include "imap.h"
#include "flag.h"
#include "log.h"


class SessionData {
public:
    SessionData()
        : readOnly( true ), mailbox( 0 ),
          uidnext( 1 ), firstUnseen( 0 ),
          imap( 0 )
    {}

    bool readOnly;
    Mailbox *mailbox;
    MessageSet msns;
    MessageSet recent;
    MessageSet expunges;
    uint uidnext;
    uint firstUnseen;
    IMAP * imap;
};


/*! \class ImapSession imapsession.h
    This class contains all data associated with an IMAP session.

    Right now, the only session data is the currently-selected Mailbox.
*/


/*! Creates a new ImapSession for the Mailbox \a m to be accessed
    using \a imap. If \a readOnly is true, the session is read-only.
*/

ImapSession::ImapSession( Mailbox *m, IMAP * imap, bool readOnly )
    : d( new SessionData )
{
    d->mailbox = m;
    d->readOnly = readOnly;
    d->imap = imap;
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


/*! Returns a pointer to the IMAP connection that's using this session. */

IMAP * ImapSession::imap() const
{
    return d->imap;
}


/*! Returns true if this is a read-only session (as created by EXAMINE),
    and false otherwise (SELECT).
*/

bool ImapSession::readOnly() const
{
    return d->readOnly;
}


/*! Returns the next UID to be used in this session. This is the same
    as Mailbox::uidnext() most of the time. It can lag behind if the
    Mailbox has changed and this session hasn't issued the
    corresponding untagged EXISTS and UIDNEXT responses.
*/

uint ImapSession::uidnext() const
{
    return d->uidnext;
}


/*! Returns the uidvalidity of the mailbox. For the moment, this is
    always the same as Mailbox::uidvalidity(), and both are always 1.
*/

uint ImapSession::uidvalidity() const
{
    return d->mailbox->uidvalidity();
}


/*! Returns the UID of the message with MSN \a msn, or 0 if there is
    no such message.
*/

uint ImapSession::uid( uint msn ) const
{
    return d->msns.value( msn );
}


/*! Returns the MSN of the message with UID \a uid, or 0 if there is
    no such message.
*/

uint ImapSession::msn( uint uid ) const
{
    return d->msns.index( uid );
}


/*! Returns the number of messages visible in this session. */

uint ImapSession::count() const
{
    return d->msns.count();
}


/*! Returns the UOD of the first unseen message in this session, or 0
    if the number isn't known.
*/

uint ImapSession::firstUnseen() const
{
    return d->firstUnseen;
}


/*! Notifies this session that its first unseen message has \a uid. */

void ImapSession::setFirstUnseen( uint uid )
{
    d->firstUnseen = uid;
}


/*! Notifies this session that it contains a message with \a uid. */

void ImapSession::insert( uint uid )
{
    d->msns.add( uid );
}


/*! Removes the message with \a uid from this session, adjusting MSNs
    as needed. This function does not emit any responses, nor does it
    cause responses to be emitted.
*/

void ImapSession::remove( uint uid )
{
    d->msns.remove( uid );
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


/*! Returns true if this ImapSession needs to refresh the client's
    world view with some EXPUNGE and/or EXISTS responses.
*/

bool ImapSession::responsesNeeded() const
{
    if ( d->mailbox->uidnext() > d->uidnext )
        return true;
    if ( !d->expunges.isEmpty() )
        return true;
    return false;
}


/*! Records that \a uids has been expunged, and that the client should
    be told about it at the earliest possible moment.
*/

void ImapSession::expunge( const MessageSet & uids )
{
    d->expunges.add( uids );
    log( "Added " + fn( uids.count() ) + " expunged messages, " +
         fn( d->expunges.count() ) + " in all" );
}


/*! Sends all necessary EXPUNGE, EXISTS and OK[UIDNEXT] responses and
    updates this ImapSession accordingly.

    emitResponses() uses Connection::writeBuffer() directly.
*/

void ImapSession::emitResponses()
{
    bool change = false;
    uint i = 1;
    while ( i < d->expunges.count() ) {
        uint uid = d->expunges.value( i );
        uint msn = d->msns.index( uid );
        if ( msn ) {
            imap()->enqueue( "* " + fn( msn ) + " EXPUNGE\r\n" );
            change = true;
            d->msns.remove( uid );
        }
        i++;
    }
    d->expunges.clear();
    uint u = d->mailbox->uidnext();
    if ( d->uidnext < u ) {
        // this is gloriously cheap: we blithely assume that all those
        // new UIDs correspond to messages. they usually do, of
        // course. if any have been deleted already and are fetched,
        // fetch will make sure there's an expunge... or a session
        // close.
        d->msns.add( d->uidnext, u - 1 );
        d->uidnext = u;
        change = true;
        (void)new ImapSessionInitializer( this, 0 );
    }

    if ( change )
        imap()->enqueue( "* " + fn( d->msns.count() ) + " EXISTS\r\n"
                         "* OK [UIDNEXT " + fn( d->uidnext ) + "]\r\n" );
}


/*! Copies the uidnext value from the mailbox, doing nothing else and
    emitting no responses.
*/

void ImapSession::updateUidnext()
{
    d->uidnext = mailbox()->uidnext();
}


class ImapSessionInitializerData
{
public:
    ImapSessionInitializerData()
        : session( 0 ), owner( 0 ),
          t( 0 ), recent( 0 ), messages( 0 ), seen( 0 ),
          oldUidnext( 0 ), newUidnext( 0 ),
          done( false )
        {}

    ImapSession * session;
    EventHandler * owner;

    Transaction * t;
    Query * recent;
    Query * messages;
    Query * seen;

    uint oldUidnext;
    uint newUidnext;

    bool done;
};


/*! \class ImapSessionInitializer imapsession.h

    The ImapSessionInitializer class performs the database queries
    needed to initialize an ImapSession.

    When completed, it notifies its owner.
*/

/*! Constructs an ImapSessionInitializer for \a session, which will
    notify \a owner when it's done.
*/

ImapSessionInitializer::ImapSessionInitializer( ImapSession * session,
                                                EventHandler * owner )
    : EventHandler(), d( new ImapSessionInitializerData )
{
    d->session = session;
    d->owner = owner;
    d->oldUidnext = d->session->uidnext();
    d->newUidnext = d->session->mailbox()->uidnext();
    d->session->updateUidnext();
    log( "Updating session on " + d->session->mailbox()->name() +
         " for UIDs [" + fn( d->oldUidnext ) + "," +
         fn( d->newUidnext ) + ">" );

    execute();
}


void ImapSessionInitializer::execute()
{
    if ( !d->t ) {
        // We select and delete the rows in recent_messages that refer
        // to our session's mailbox. Concurrent Selects of the same
        // mailbox will block until this transaction has committed.

        d->t = new Transaction( this );

        d->recent = new Query( "select * from recent_messages where "
                               "mailbox=$1 and uid>=$2 and uid<$3 for update",
                               this );
        d->recent->bind( 1, d->session->mailbox()->id() );
        d->recent->bind( 2, d->oldUidnext );
        d->recent->bind( 3, d->newUidnext );
        d->t->enqueue( d->recent );

        if ( !d->session->readOnly() ) {
            Query *q = new Query( "delete from recent_messages where "
                                  "mailbox=$1 and uid>=$2 and uid<$3", this );
            q->bind( 1, d->session->mailbox()->id() );
            q->bind( 2, d->oldUidnext );
            q->bind( 3, d->newUidnext );
            d->t->enqueue( q );
        }

        d->t->commit();

        d->messages
            = new Query( "select uid "
                         "from messages where mailbox=$1 and "
                         "uid>=$2 and uid<$3",
                         this );
        d->messages->bind( 1, d->session->mailbox()->id() );
        d->messages->bind( 2, d->oldUidnext );
        d->messages->bind( 3, d->newUidnext );
        d->messages->execute();

        d->seen 
            = new Query( "select uid from messages "
                         "where mailbox=$1 and not(uid in ("
                         "select uid from flags where "
                         "mailbox=$1 and flag="
                         "(select id from flag_names where name='\\Seen'))) "
                         "order by uid limit 1",
                         this );
        d->seen->bind( 1, d->session->mailbox()->id() );
        d->seen->execute();
    }

    Row * r = 0;
    while ( (r = d->recent->nextRow()) != 0 )
        d->session->addRecent( r->getInt( "uid" ) );

    while ( (r=d->messages->nextRow()) != 0 ) {
        uint uid = r->getInt( "uid" );
        d->session->insert( uid );
    }

    while( (r=d->seen->nextRow()) )
        d->session->setFirstUnseen( r->getInt( "uid" ) );

    if ( !d->messages->done() || !d->recent->done() || !d->seen->done() ||
         !d->t->done() )
        return;

    log( "Saw " + fn( d->messages->rows() ) + " new messages, " +
         fn( d->recent->rows() ) + " recent ones",
         Log::Debug );
    d->done = true;
    if ( d->owner )
        d->owner->execute();
}


/*! Returns true once the initializer has done its job, and false
    until then.
*/

bool ImapSessionInitializer::done() const
{
    return d->done;
}


/*! Returns a message set containing all the UIDs that have been
    expunged in the database, but not yet reported to the client.
*/

const MessageSet & ImapSession::expunged() const
{
    return d->expunges;
}



/*! Returns a message set containing all the messages that are
    currently valid in this session. This may include expunged
    messages.
*/

const MessageSet & ImapSession::messages() const
{
    return d->msns;
}
