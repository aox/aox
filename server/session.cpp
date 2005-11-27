// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "session.h"

#include "transaction.h"
#include "messageset.h"
#include "selector.h"
#include "mailbox.h"
#include "message.h"
#include "event.h"
#include "query.h"
#include "flag.h"
#include "log.h"


class SessionData
    : public Garbage
{
public:
    SessionData()
        : readOnly( true ),
          watchers( 0 ),
          initialiser( 0 ),
          mailbox( 0 ),
          uidnext( 0 ), firstUnseen( 0 ),
          permissions( 0 ),
          announced( 0 )
    {}

    bool readOnly;
    List<EventHandler> * watchers;
    SessionInitialiser * initialiser;
    Mailbox * mailbox;
    MessageSet msns;
    MessageSet recent;
    MessageSet expunges;
    uint uidnext;
    uint firstUnseen;
    Permissions * permissions;
    uint announced;
};


/*! \class Session session.h
    This class contains all data associated with the single use of a
    Mailbox, such as the number of messages visible, etc. Subclasses
    provide some protocol-specific actions.
*/

/*! Creates a new Session for the Mailbox \a m. If \a readOnly is true,
    the session is read-only.
*/

Session::Session( Mailbox *m, bool readOnly )
    : d( new SessionData )
{
    d->mailbox = m;
    d->readOnly = readOnly;
}


/*! Exists only to satisfy GCC.
*/

Session::~Session()
{
}


/*! Returns true if this Session has updated itself from the database.
*/

bool Session::initialised() const
{
    if ( !d->uidnext )
        return false;
    if ( d->initialiser )
        return false;
    return true;
}


/*! Returns a pointer to the currently selected Mailbox, or 0 if there
    isn't one.
*/

Mailbox *Session::mailbox() const
{
    return d->mailbox;
}


/*! Returns true if this is a read-only session (as created by EXAMINE),
    and false otherwise (SELECT).
*/

bool Session::readOnly() const
{
    return d->readOnly;
}


/*! Returns a pointer to the Permissions object owned by this session,
    or 0 if none has been created (by Select). This object is ready to
    answer queries (with allows()) because Select waited for it to be.
*/

Permissions *Session::permissions() const
{
    return d->permissions;
}


/*! Sets the Permissions object for this session to \a p. Used only by
    Select. Session assumes that \a p is Permissions::ready().
*/

void Session::setPermissions( Permissions *p )
{
    d->permissions = p;
}


/*! Returns true only if this session knows that its user has the right
    \a r. If the session does not know, or the user doesn't have the
    right, it returns false.
*/

bool Session::allows( Permissions::Right r )
{
    return d->permissions->allowed( r );
}


/*! Returns the next UID to be used in this session. This is the same
    as Mailbox::uidnext() most of the time. It can lag behind if the
    Mailbox has changed and this session hasn't issued the
    corresponding untagged EXISTS and UIDNEXT responses.
*/

uint Session::uidnext() const
{
    return d->uidnext;
}


/*! Returns the uidvalidity of the mailbox. For the moment, this is
    always the same as Mailbox::uidvalidity(), and both are always 1.
*/

uint Session::uidvalidity() const
{
    return d->mailbox->uidvalidity();
}


/*! Returns the UID of the message with MSN \a msn, or 0 if there is
    no such message.
*/

uint Session::uid( uint msn ) const
{
    return d->msns.value( msn );
}


/*! Returns the MSN of the message with UID \a uid, or 0 if there is
    no such message.
*/

uint Session::msn( uint uid ) const
{
    return d->msns.index( uid );
}


/*! Returns the number of messages visible in this session. */

uint Session::count() const
{
    return d->msns.count();
}


/*! Returns the UID of the first unseen message in this session, or 0
    if the number isn't known.
*/

uint Session::firstUnseen() const
{
    return d->firstUnseen;
}


/*! Notifies this session that its first unseen message has \a uid. */

void Session::setFirstUnseen( uint uid )
{
    d->firstUnseen = uid;
}


/*! Notifies this session that it contains a message with \a uid. */

void Session::insert( uint uid )
{
    d->msns.add( uid );
}


/*! Notifies this session that it contains messages with UIDs from \a
    lowest to \a highest (in addition to whatever other messages it
    may contain). Both \a lowest and \a highest are inserted.
*/

void Session::insert( uint lowest, uint highest )
{
    d->msns.add( lowest, highest );
}


/*! Removes the message with \a uid from this session, adjusting MSNs
    as needed. This function does not emit any responses, nor does it
    cause responses to be emitted.
*/

void Session::remove( uint uid )
{
    d->msns.remove( uid );
}


/*! Returns a MessageSet containing all messages marked "\Recent" in
    this session.
*/

MessageSet Session::recent() const
{
    return d->recent;
}


/*! Returns true only if the message \a uid is marked as "\Recent" in
    this session.
*/

bool Session::isRecent( uint uid ) const
{
    return d->recent.contains( uid );
}


/*! Marks the message \a uid as "\Recent" in this session. */

void Session::addRecent( uint uid )
{
    d->recent.add( uid );
}


/*! Returns true if this Session needs to refresh the client's
    world view with some EXPUNGE and/or EXISTS responses.
*/

bool Session::responsesNeeded() const
{
    if ( d->mailbox->uidnext() > d->uidnext )
        return true;
    if ( d->mailbox->type() == Mailbox::View &&
         d->mailbox->source()->uidnext() > d->mailbox->sourceUidnext() )
        return true;
    if ( !d->expunges.isEmpty() )
        return true;
    return false;
}


/*! Records that \a uids has been expunged, and that the client should
    be told about it at the earliest possible moment.
*/

void Session::expunge( const MessageSet & uids )
{
    if ( uids.isEmpty() )
        return;
    d->expunges.add( uids );
}


/*! Sends all necessary EXPUNGE, EXISTS and OK[UIDNEXT] responses and
    updates this Session accordingly.

    emitResponses() uses Connection::writeBuffer() directly.
*/

void Session::emitResponses()
{
    bool change = false;
    uint i = 1;
    while ( i <= d->expunges.count() ) {
        uint uid = d->expunges.value( i );
        uint msn = d->msns.index( uid );
        if ( msn ) {
            emitExpunge( msn );
            change = true;
            d->msns.remove( uid );
        }
        i++;
    }
    d->expunges.clear();
    if ( d->uidnext < d->mailbox->uidnext() ) {
        change = true;
        if ( !d->initialiser )
            d->initialiser = new SessionInitialiser( this, 0 );
    }

    if ( change )
        emitExists( d->msns.count() );
}


/*! \fn Session::emitExpunge( uint msn )
    Does whatever the protocol requires when a message numbered \a msn
    is expunged. When this function is called, uid() and msn() are still
    valid.
*/

void Session::emitExpunge( uint )
{
}


/*! \fn Session::emitExists( uint number )
    Does whatever the protocol requires when the number of messages in
    the Mailbox changes to \a number.
*/

void Session::emitExists( uint )
{
}


/*! Sets our uidnext value to \a u. Used only by the SessionInitialiser.
*/

void Session::setUidnext( uint u )
{
    d->uidnext = u;
}


/*! Returns the last UIDNEXT value that this session has announced.
    (Used to decide if a new one needs to be announced.)

    This function may be misnamed, and may not be necessary at all.
*/

uint Session::announced() const
{
    return d->announced;
}


/*! Sets the last announced UIDNEXT value to \a n.
*/

void Session::setAnnounced( uint n )
{
    d->announced = n;
}


/*! Refreshes this session, notifying \a handler when it's done.
*/

void Session::refresh( EventHandler * handler )
{
    if ( handler && d->initialiser )
        d->initialiser->addWatcher( handler );
    else if ( d->uidnext < d->mailbox->uidnext() )
        d->initialiser = new SessionInitialiser( this, handler );
}




class SessionInitialiserData
    : public Garbage
{
public:
    SessionInitialiserData()
        : session( 0 ),
          t( 0 ), recent( 0 ), messages( 0 ), seen( 0 ),
          oldUidnext( 0 ), newUidnext( 0 ),
          done( false )
        {}

    Session * session;
    List<EventHandler> watchers;

    Transaction * t;
    Query * recent;
    Query * messages;
    Query * seen;

    uint oldUidnext;
    uint newUidnext;

    MessageSet expunged;

    bool done;
};


/*! \class SessionInitialiser imapsession.h

    The SessionInitialiser class performs the database queries
    needed to initialise an Session.

    When it's created, it immediately informs its owner that so-and-so
    many messages exist and returns. Later, it issues database queries
    to check that the messages do exist, and if any don't, it coerces
    its Session to emit corresponding expunges.

    When completed, it notifies its owner.
*/

/*! Constructs an SessionInitialiser for \a session, which will
    notify \a owner when it's done.
*/

SessionInitialiser::SessionInitialiser( Session * session,
                                        EventHandler * owner )
    : EventHandler(), d( new SessionInitialiserData )
{
    d->session = session;
    addWatcher( owner );
    d->oldUidnext = d->session->uidnext();
    d->newUidnext = d->session->mailbox()->uidnext();
    if ( d->oldUidnext >= d->newUidnext )
        return;

    log( "Updating session on " + d->session->mailbox()->name() +
         " for UIDs [" + fn( d->oldUidnext ) + "," +
         fn( d->newUidnext ) + ">" );

    d->session->setUidnext( d->newUidnext );
    d->session->insert( d->oldUidnext, d->newUidnext-1 );
    d->expunged.add( d->oldUidnext, d->newUidnext-1 );
    execute();
}


void SessionInitialiser::execute()
{
    if ( d->done )
        return;

    if ( !d->t ) {
        // We update first_recent for our mailbox. Concurrent selects of
        // this mailbox will block until this transaction has committed.

        Mailbox * m = d->session->mailbox();

        d->t = new Transaction( this );

        if ( d->session->readOnly() )
            d->recent = new Query( "select first_recent from mailboxes "
                                   "where id=$1", this );
        else
            d->recent = new Query( "select first_recent from mailboxes "
                                   "where id=$1 for update", this );
        d->recent->bind( 1, d->session->mailbox()->id() );
        d->t->enqueue( d->recent );

        if ( !d->session->readOnly() ) {
            Query *q = new Query( "update mailboxes set first_recent=$2 "
                                  "where id=$1", this );
            q->bind( 1, d->session->mailbox()->id() );
            q->bind( 2, d->newUidnext );
            d->t->enqueue( q );
        }

        if ( m->ordinary() ) {
            d->messages =
                new Query( "select uid from messages where mailbox=$1 "
                           "and uid>=$2 and uid<$3", this );
        }
        else {
            Query * q;

            q = new Query( "select uidnext from mailboxes where id=$1 "
                           "for update", this );
            q->bind( 1, m->id() );
            d->t->enqueue( q );

            q = new Query( "create temporary sequence vs start with " +
                           fn( m->uidnext() ), this );
            d->t->enqueue( q );

            MessageSet ms;
            ms.add( m->sourceUidnext(), UINT_MAX );

            Selector * sel = new Selector;
            sel->add( new Selector( ms ) );
            sel->add( Selector::fromString( m->selector() ) );
            sel->simplify();

            q = sel->query( 0, m->source(), 0, 0 );

            uint view = sel->placeHolder();
            uint source = sel->placeHolder();

            String s( "insert into view_messages (view,uid,source,suid) "
                      "select $" + fn( view ) + "::int,nextval('vs'),$" +
                      fn( source ) + "::int,uid from (" + q->string() + ")"
                      " as THANK_YOU_SQL_WEENIES" );

            q->setString( s );
            q->bind( view, m->id() );
            q->bind( source, m->source()->id() );
            d->t->enqueue( q );

            q = new Query( "update mailboxes set uidnext=nextval('vs') "
                           "where id=$1", this );
            q->bind( 1, m->id() );
            d->t->enqueue( q );

            q = new Query( "update views set suidnext="
                           "(select uidnext from mailboxes where id=$1) "
                           "where view=$2", this );
            q->bind( 1, m->source()->id() );
            q->bind( 2, m->id() );
            d->t->enqueue( q );

            d->t->enqueue( m->refresh() );

            d->messages =
                new Query( "select uid from view_messages where "
                           "view=$1 and uid>=$2 and uid<$3", this );

            q = new Query( "drop sequence vs", this );
            d->t->enqueue( q );
        }

        d->messages->bind( 1, m->id() );
        d->messages->bind( 2, d->oldUidnext );
        d->messages->bind( 3, d->newUidnext );

        d->t->enqueue( d->messages );
        d->t->commit();

        if ( !d->session->firstUnseen() ) {
            // XXX: will this work if the sysadmin has set the flag
            // name to \seen or \SEEN? I think not?
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
    }

    Row * r = 0;

    while ( (r=d->messages->nextRow()) != 0 ) {
        uint uid = r->getInt( "uid" );
        d->expunged.remove( uid );
    }

    if ( (r=d->recent->nextRow()) != 0 ) {
        uint recent = r->getInt( "first_recent" );
        uint n = recent;
        while ( n < d->newUidnext )
            d->session->addRecent( n++ );
    }

    if ( d->seen )
        while( (r=d->seen->nextRow()) )
            d->session->setFirstUnseen( r->getInt( "uid" ) );

    if ( !d->t->done() )
        return;
    if ( !d->messages->done() )
        return;
    if ( d->seen && !d->seen->done() )
        return;

    d->done = true;
    d->session->expunge( d->expunged );
    d->session->removeSessionInitialiser();

    List<EventHandler>::Iterator it( d->watchers );
    while ( it ) {
        EventHandler * e = it;
        ++it;
        e->execute();
    }
}


/*! Returns true once the initialiser has done its job, and false
    until then.
*/

bool SessionInitialiser::done() const
{
    return d->done;
}


/*! Returns a message set containing all the UIDs that have been
    expunged in the database, but not yet reported to the client.
*/

const MessageSet & Session::expunged() const
{
    return d->expunges;
}


/*! Returns a message set containing all the messages that are
    currently valid in this session. This may include expunged
    messages.
*/

const MessageSet & Session::messages() const
{
    return d->msns;
}


/*! Clears the list of expunged messages without calling
    emitExpunge().
*/

void Session::clearExpunged()
{
    d->msns.remove( d->expunges );
    d->expunges.clear();
}


/*! The SessionInitialiser calls this when initialised() can return
    true. Noone else should ever call it.
*/

void Session::removeSessionInitialiser()
{
    d->initialiser = 0;
}


/*! Records that \a e should be notified when the initialiser has
    finished its work.
*/

void SessionInitialiser::addWatcher( EventHandler * e )
{
    if ( e )
        d->watchers.append( e );
}
