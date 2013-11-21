// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "session.h"

#include "transaction.h"
#include "integerset.h"
#include "allocator.h"
#include "selector.h"
#include "mailbox.h"
#include "message.h"
#include "cache.h"
#include "event.h"
#include "query.h"
#include "scope.h"
#include "flag.h"
#include "map.h"
#include "log.h"


class SessionData
    : public Garbage
{
public:
    SessionData()
        : readOnly( true ),
          mailbox( 0 ), connection( 0 ),
          uidnext( 1 ), nextModSeq( 1 ),
          permissions( 0 )
    {}

    bool readOnly;
    Mailbox * mailbox;
    Connection * connection;
    IntegerSet msns;
    IntegerSet recent;
    IntegerSet expunges;
    uint uidnext;
    int64 nextModSeq;
    Permissions * permissions;
    IntegerSet unannounced;

    class CachedData
        : public Garbage
    {
    public:
        CachedData(): Garbage(), uidnext( 0 ), nextModSeq( 1 ) {}
        uint uidnext;
        int64 nextModSeq;
        IntegerSet msns;
    };

    class SessionCache
        : public Cache
    {
    public:
        SessionCache(): Cache( 3 ) {}
        Map<CachedData> data;
        void clear() { data.clear(); }
    };
};


static SessionData::SessionCache * cache = 0;


/*! \class Session session.h
    This class contains all data associated with the single use of a
    Mailbox, such as the number of messages visible, etc. Subclasses
    provide some protocol-specific actions.
*/

/*! Creates a new Session for the Mailbox \a m tied to Connection \a
    c. If \a readOnly is true, the session is read-only.
*/

Session::Session( Mailbox * m, Connection * c, bool readOnly )
    : d( new SessionData )
{
    d->mailbox = m;
    d->connection = c;
    d->readOnly = readOnly;
    Session * other = 0;
    if ( d->mailbox->sessions() )
        other = d->mailbox->sessions()->firstElement();
    d->mailbox->addSession( this );
    Flag::addWatcher( this );
    if ( other ) {
        d->uidnext = other->d->uidnext;
        d->nextModSeq = other->d->nextModSeq;
        d->msns.add( other->d->msns );
        d->msns.add( other->d->unannounced );
        d->msns.remove( other->d->expunges );
    }
    else if ( cache ) {
        SessionData::CachedData * cd = cache->data.find( m->id() );
        if ( cd ) {
            d->uidnext = cd->uidnext;
            d->nextModSeq = cd->nextModSeq;
            d->msns.add( cd->msns );
        }
    }
    (void)new SessionInitialiser( m, 0 );
}


/*! Returns a pointer to the Connection served by this Session.
*/

Connection * Session::connection() const
{
    return d->connection;
}


/*! Exists to satisfy g++.
*/

Session::~Session()
{
    end();
}


/*! Ensures that the Mailbox will not keep this object alive. */

void Session::end()
{
    if ( !d->mailbox )
        return;

    Flag::removeWatcher( this );

    d->mailbox->removeSession( this );
    if ( d->mailbox->sessions() )
        return;

    if ( d->readOnly )
        return;

    if ( !::cache )
        ::cache = new SessionData::SessionCache;
    SessionData::CachedData * cd = ::cache->data.find( d->mailbox->id() );
    if ( !cd ) {
        cd = new SessionData::CachedData;
        ::cache->data.insert( d->mailbox->id(), cd );
    }
    cd->uidnext = d->uidnext;
    cd->msns = d->msns;
    cd->nextModSeq = d->nextModSeq;
    cd->msns.remove( d->expunges );
}


/*! Aborts this Session. The default implementation disconnects the
    client, subclasses may be more subtle.
*/

void Session::abort()
{
    if ( !d->connection )
        return;

    log( "Need to close connection in order to abort this session" );
    Scope x( d->connection->log() );
    log( "Session aborted" );
    d->connection->react( Connection::Close );
}


/*! Returns true if this Session has updated itself from the database.
*/

bool Session::initialised() const
{
    if ( d->nextModSeq < d->mailbox->nextModSeq() )
        return false;
    if ( d->uidnext < d->mailbox->uidnext() )
        return false;
    return true;
}


/*! Returns true if this session is known to contain no messages
    (ie. both messages() and unannounced() return empty sets), and
    true if the mailbox is nonempty or its count is not known.
*/

bool Session::isEmpty() const
{
    if ( d->mailbox->uidnext() == 1 )
        return true;
    if ( !d->msns.isEmpty() )
        return false;
    if ( !d->unannounced.isEmpty() )
        return false;
    if ( !initialised() )
        return false;
    return true;
}


/*! Returns a pointer to the currently selected Mailbox, or 0 if there
    isn't one.
*/

Mailbox * Session::mailbox() const
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

Permissions * Session::permissions() const
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


/*! Returns the UID of the highest-numbered message, or uidnext()-1 if
    the mailbox is empty, or 1 if uidnext() is 1.
*/

uint Session::largestUid() const
{
    if ( d->uidnext == 1 )
        return 1;
    else if ( d->msns.isEmpty() )
        return d->uidnext - 1;
    return d->msns.largest();
}


/*! Returns a IntegerSet containing all messages marked "\Recent" in
    this session.
*/

IntegerSet Session::recent() const
{
    return d->recent.intersection( d->msns );
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


/*! Marks \a num messages with uid starting at \a start as "\Recent" in
    this session. */

void Session::addRecent( uint start, uint num )
{
    while ( num-- )
        d->recent.add( start++ );
}


/*! Records that \a uids has been expunged and that the clients should
    be told about it at the earliest possible moment.
*/

void Session::expunge( const IntegerSet & uids )
{
    d->expunges.add( uids );
}


/*! This virtual function is responsible for telling the client about
    any updates it need to hear. If \a t is non-null and any database
    work is needed, it should use a subtransaction of \a t.
*/

void Session::emitUpdates( Transaction * t )
{
    t = t;
}


/*! Sets our uidnext value to \a u. Used only by the SessionInitialiser.
*/

void Session::setUidnext( uint u )
{
    d->uidnext = u;
}


class SessionInitialiserData
    : public Garbage
{
public:
    SessionInitialiserData()
        : mailbox( 0 ),
          t( 0 ), recent( 0 ), messages( 0 ), expunges( 0 ),
          oldUidnext( 0 ), newUidnext( 0 ),
          state( NoTransaction ),
          changeRecent( false )
        {}

    Mailbox * mailbox;
    List<Session> sessions;

    Transaction * t;
    Query * recent;
    Query * messages;
    Query * expunges;

    uint oldUidnext;
    uint newUidnext;
    int64 oldModSeq;
    int64 newModSeq;

    enum State { NoTransaction, WaitingForLock, HaveUidnext,
                 ReceivingChanges, Updated, QueriesDone };
    State state;

    bool changeRecent;
};


/*! \class SessionInitialiser session.h

    The SessionInitialiser class performs the database queries
    needed to initialise or update Session objects.

    When it's created, it tries to see whether the database work can
    be skipped. If not, it does all the necessary database queries and
    updates, and finally informs the Session objects of new and
    modified Message objects.
*/

/*! Constructs an SessionInitialiser for \a mailbox. If \a t is
    non-null, then the initialiser will use a subtransaction of \a t
    for its work.
*/

SessionInitialiser::SessionInitialiser( Mailbox * mailbox, Transaction * t )
    : EventHandler(), d( new SessionInitialiserData )
{
    setLog( new Log );
    d->mailbox = mailbox;
    if ( t )
        d->t = t->subTransaction( this );
    execute();
}


void SessionInitialiser::execute()
{
    Scope x( log() );
    SessionInitialiserData::State state = d->state;
    do {
        state = d->state;
        switch ( d->state ) {
        case SessionInitialiserData::NoTransaction:
            findSessions();
            if ( d->sessions.isEmpty() ) {
                emitUpdates();
                d->state = SessionInitialiserData::QueriesDone;
            }
            else {
                grabLock();
                d->state = SessionInitialiserData::WaitingForLock;
            }
            break;
        case SessionInitialiserData::SessionInitialiserData::WaitingForLock:
            findRecent();
            if ( !d->recent || d->recent->done() )
                d->state = SessionInitialiserData::HaveUidnext;
            break;
        case SessionInitialiserData::HaveUidnext:
            findMailboxChanges();
            d->state = SessionInitialiserData::ReceivingChanges;
            break;
        case SessionInitialiserData::ReceivingChanges:
            recordMailboxChanges();
            recordExpunges();
            if ( d->messages->done() &&
                 ( !d->expunges || d->expunges->done() ) )
                d->state = SessionInitialiserData::Updated;
            break;
        case SessionInitialiserData::Updated:
            releaseLock(); // may change d->state
            break;
        case SessionInitialiserData::QueriesDone:
            break;
        }
    } while ( state != d->state );
    if ( d->t && d->t->failed() ) {
        releaseLock();
        d->t = 0;
    }
    // when we come down here, we either have a callback from a query
    // or we don't. if we don't, we're done and Allocator will deal
    // with the object.
}


/*! Finds all sessions that may be updated by this initialiser.
    Doesn't lock anything.
*/

void SessionInitialiser::findSessions()
{
    d->newUidnext = d->mailbox->uidnext();
    d->newModSeq = d->mailbox->nextModSeq();
    d->oldUidnext = d->newUidnext;
    d->oldModSeq = d->newModSeq;
    List<Session>::Iterator i( d->mailbox->sessions() );
    while ( i ) {
        Session * s = i;
        ++i;
        Connection * c = s->connection();
        if ( c && c->state() == Connection::Invalid ) {
            Scope x( c->log() );
            log( "Mailbox session found for dead connection.", Log::Error );
            s->end();
        }
        else {
            d->sessions.append( s );
            if ( s->uidnext() < d->oldUidnext )
                d->oldUidnext = s->uidnext();
            if ( s->nextModSeq() < d->oldModSeq )
                d->oldModSeq = s->nextModSeq();
        }
    }
    // if some session is behind the mailbox, carry out an update
    if ( d->newUidnext > d->oldUidnext ||
         d->newModSeq > d->oldModSeq )
        return;
    // if none are, and the mailbox is ordinary, we don't need anything
    if ( d->mailbox->ordinary() )
        d->sessions.clear();
    // otherwise we may need to do work
}


/*! Grabs enough locks on the database that we can update what we need
    to update: Only one session must get the "\recent" flag.
*/

void SessionInitialiser::grabLock()
{
    d->changeRecent = false;
    uint highestRecent = 0;
    List<Session>::Iterator i( d->sessions );
    while ( i && !d->changeRecent ) {
        if ( !i->readOnly() )
            d->changeRecent = true;
        uint r = i->d->recent.largest(); // XXX needs friend
        if ( r > highestRecent )
            highestRecent = r;
        ++i;
    }

    if ( highestRecent + 1 == d->newUidnext )
        d->changeRecent = false;

    log( "Updating " + fn( d->sessions.count() ) + " (of " +
         fn( d->mailbox->sessions() ? d->mailbox->sessions()->count() : 0 ) +
         ") session(s) on " +
         d->mailbox->name().ascii() +
         " for modseq [" + fn( d->oldModSeq ) + "," +
         fn( d->newModSeq ) + ">, UID [" + fn( d->oldUidnext ) + "," +
         fn( d->newUidnext ) + ">" );

    if ( !d->t && d->changeRecent )
        d->t = new Transaction( this );

    if ( d->changeRecent )
        d->recent = new Query( "select first_recent from mailboxes "
                               "where id=$1 for update", this );
    else if ( highestRecent < d->newUidnext - 1 )
        d->recent = new Query( "select first_recent from mailboxes "
                               "where id=$1", this );
    if ( d->recent ) {
        d->recent->bind( 1, d->mailbox->id() );
        submit( d->recent );
    }

    return;
}


/*! Commits the transaction, releasing the locks we've held, and
    updates the state. After this we're done.
*/

void SessionInitialiser::releaseLock()
{
    emitUpdates();
    if ( d->t ) {
        d->t->commit();
        if ( !d->t->failed() && !d->t->done() )
            return;

        if ( !d->t->failed() )
            d->state = SessionInitialiserData::QueriesDone;
        d->t = 0;
    }
    else {
        d->state = SessionInitialiserData::QueriesDone;
    }
}


/*! Fetches the "\recent" data from the database and sends an update
    to the database if we have to change it. Note that this doesn't
    release our lock.
*/

void SessionInitialiser::findRecent()
{
    if ( !d->recent )
        return;
    Row * r = d->recent->nextRow();
    if ( !r )
        return;

    uint recent = r->getInt( "first_recent" );
    List<Session>::Iterator i( d->sessions );
    while ( i && i->readOnly() )
        ++i;
    Session * s = i;
    if ( !s )
        s = d->sessions.firstElement(); // happens if all sessions are RO
    if ( !s )
        return; // could happen if a session violently dies
    if ( recent >= d->newUidnext )
        return; // just to avoid the unnecessary update below
    while ( recent < d->newUidnext )
        s->addRecent( recent++ );

    if ( !d->changeRecent )
        return;
    Query * q = new Query( "update mailboxes set first_recent=$2 "
                           "where id=$1", 0 );
    q->bind( 1, d->mailbox->id() );
    q->bind( 2, recent );
    submit( q );
}


/*! Issues a query to find new and changed messages in the
    mailbox, and one to find newly expunged messages.
*/

void SessionInitialiser::findMailboxChanges()
{
    bool initialising = false;
    if ( d->oldUidnext <= 1 )
        initialising = true;
    EString msgs = "select mm.uid, mm.modseq from mailbox_messages mm "
                  "where mm.mailbox=$1 and mm.uid<$2";

    // if we know we'll see one new modseq and at least one new
    // message, we could skip the test on mm.modseq.
    if ( !initialising )
        msgs.append( " and (mm.uid>=$3 or mm.modseq>=$4)" );

    d->messages = new Query( msgs, this );
    d->messages->bind( 1, d->mailbox->id() );
    d->messages->bind( 2, d->newUidnext );
    if ( !initialising ) {
        d->messages->bind( 3, d->oldUidnext );
        d->messages->bind( 4, d->oldModSeq );
    }
    submit( d->messages );

    if ( initialising )
        return;

    d->expunges = new Query( "select uid from deleted_messages "
                             "where mailbox=$1 and modseq>=$2",
                             this );
    d->expunges->bind( 1, d->mailbox->id() );
    d->expunges->bind( 2, d->oldModSeq );
    submit( d->expunges );
}


/*! Parses the results of the Query generated by findMailboxChanges()
    and updates each Session.
*/

void SessionInitialiser::recordMailboxChanges()
{
    Row * r = 0;
    while ( (r=d->messages->nextRow()) != 0 ) {
        uint uid = r->getInt( "uid" );
        addToSessions( uid, r->getBigint( "modseq" ) );
    }
}


/*! Finds any expunges stored in the db, but new to us, and records
    those in all the sessions.
*/

void SessionInitialiser::recordExpunges()
{
    if ( !d->expunges )
        return;
    Row * r = 0;
    IntegerSet uids;
    while ( (r=d->expunges->nextRow()) != 0 )
        uids.add( r->getInt( "uid" ) );
    if ( uids.isEmpty() )
        return;

    List<Session>::Iterator i( d->sessions );
    while ( i ) {
        Session * s = i;
        ++i;
        s->expunge( uids );
    }
}


/*! Persuades each Session to emit its responses.
*/

void SessionInitialiser::emitUpdates()
{
    List<Session>::Iterator s( d->sessions );
    while ( s ) {
        if ( s->nextModSeq() < d->newModSeq )
            s->setNextModSeq( d->newModSeq );
        if ( s->uidnext() < d->newUidnext )
            s->setUidnext( d->newUidnext );
        ++s;
    }
    s = d->sessions.first();
    while ( s ) {
        s->emitUpdates( d->t );
        ++s;
    }
    d->sessions.clear();
}


/*! Adds \a uid with modseq \a ms to each session to be announced as
    changed or new.
*/

void SessionInitialiser::addToSessions( uint uid, int64 ms )
{
    List<Session>::Iterator i( d->sessions );
    while ( i ) {
        Session * s = i;
        ++i;
        if ( uid >= s->uidnext() || !ms || ms >= s->nextModSeq() )
            s->addUnannounced( uid );
    }
}


/*! This private helper submits \a q via our Transaction if we're
    using one, directly if not.
*/

void SessionInitialiser::submit( class Query * q )
{
    if ( d->t ) {
        d->t->enqueue( q );
        d->t->execute();
    }
    else {
        q->execute();
    }
}


/*! Returns a message set containing all the UIDs that have been
    expunged in the database, but not yet reported to the client.
*/

const IntegerSet & Session::expunged() const
{
    return d->expunges;
}


/*! Returns a message set containing all the messages that are
    currently valid in this session. This may include expunged
    messages.
*/

const IntegerSet & Session::messages() const
{
    return d->msns;
}


/*! Records that the client has been told that \a uid no longer
    exists.

    This is IMAP stuff infesting Session.
*/

void Session::clearExpunged( uint uid )
{
    d->msns.remove( uid );
    d->expunges.remove( uid );
    d->unannounced.remove( uid );
}


/*! Returns what setNextModSeq() set. The initial value is 0. */

int64 Session::nextModSeq() const
{
    return d->nextModSeq;
}


/*! Records that the next possible modseq for a message in this
    session is \a ms or higher.
*/

void Session::setNextModSeq( int64 ms ) const
{
    d->nextModSeq = ms;
}


/*! Returns whatever has been set using addUnannounced() and not yet
    cleared by clearUnannounced().
*/

IntegerSet Session::unannounced() const
{
    return d->unannounced;
}


/*! Records that the messages in \a s have been added to the mailbox
    or changed, and should be announced to the client and if necessary
    added to the session.
*/

void Session::addUnannounced( const IntegerSet & s )
{
    d->unannounced.add( s );
}


/*! Records that \a uid has been added to the mailbox or changed, and
    should be announced to the client and if necessary added to the
    session.
*/

void Session::addUnannounced( uint uid )
{
    d->unannounced.add( uid );
}


/*! Records that everything in unannounced() has been announced. */

void Session::clearUnannounced()
{
    d->msns.add( d->unannounced );
    d->unannounced.clear();
}


/*! Does whatever is necessary to tell the client about new
    flags. This is really a hack for ImapSession.
*/

void Session::sendFlagUpdate()
{
}


class SessionPreloaderData
    : public Garbage
{
public:
    SessionPreloaderData(): owner( 0 ), lock( 0 ), uids( 0 ), done( false ) {}

    List<Mailbox> l;
    EventHandler * owner;
    Query * lock;
    Query * uids;
    bool done;
};


/*! \class SessionPreloader session.h

    Loads information about selected mailboxes into the session cache,
    so that newly-created sessions have access to it straightaway.
*/

/*!  Constructs a SessionPreloader which will preload the session cache
     with information about \a mailboxes, and then notify \a handler.

     If the cache already contains all that information, then
     execute() will set done() and not call \a handler.
*/

SessionPreloader::SessionPreloader( List<Mailbox> * mailboxes,
                                  EventHandler * handler )
    : d( new SessionPreloaderData )
{
    List<Mailbox>::Iterator i( mailboxes );
    while ( i ) {
        d->l.append( i );
        ++i;
    }
    d->owner = handler;
}


void SessionPreloader::execute()
{
    if ( !::cache )
        ::cache = new SessionData::SessionCache;

    if ( !d->uids ) {
        IntegerSet e;
        IntegerSet a;
        IntegerSet s;
        List<Mailbox>::Iterator i( d->l );
        while ( i ) {
            if ( i->uidnext() <= 1 )
                e.add( i->id() );
            else if ( ::cache->data.find( i->id() ) )
                a.add( i->id() );
            else
                s.add( i->id() );
            ++i;
        }
        if ( s.count() > 2 ) {
            log( "Session preloader: " +
                 fn( a.count() ) + " already cached, " +
                 fn( e.count() ) + " mailboxes empty, " +
                 fn( s.count() ) + " can be preloaded." );
            Transaction * t = new Transaction( this );
            d->lock
                = new Query( "select id, uidnext, nextmodseq, first_recent "
                             "from mailboxes where id=any($1) "
                             "order by id for update", 0 );
            d->lock->bind( 1, s );
            t->enqueue( d->lock );
            d->uids = new Query( "select mailbox, uid from mailbox_messages "
                                 "where mailbox=any($1)", this );
            d->uids->bind( 1, s );
            t->enqueue( d->uids );
            t->commit();
        }
        else {
            // for just 0-2 mailboxes this query won't be a net gain
            d->done = true;
        }
    }

    if ( !d->uids || !d->uids->done() )
        return;

    while ( d->lock->hasResults() ) {
        Row * r = d->lock->nextRow();

        SessionData::CachedData * cd = ::cache->data.find( r->getInt( "id" ) );
        if ( !cd ) {
            cd = new SessionData::CachedData;
            ::cache->data.insert( r->getInt( "id" ), cd );
        }

        cd->uidnext = r->getInt( "uidnext" );
        cd->nextModSeq = r->getBigint( "nextmodseq" );

        // if there are recent messages the next SI has to look, so
        // force it. sigh. recent is such a mess.
        if ( cd->uidnext > (uint)r->getInt( "first_recent" ) )
            cd->nextModSeq--;
    }

    while ( d->uids->hasResults() ) {
        Row * r = d->uids->nextRow();
        SessionData::CachedData * cd =
            ::cache->data.find( r->getInt( "mailbox" ) );
        if ( cd )
            cd->msns.add( r->getInt( "uid" ) );
    }

    d->done = true;
    d->owner->notify();
}


/*! Returns true if the SessionPreloader has done all it's going to do,
    and false if it hasn't.

*/

bool SessionPreloader::done()
{
    return d->done;
}
