// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "session.h"

#include "transaction.h"
#include "messageset.h"
#include "allocator.h"
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
          initialiser( 0 ),
          mailbox( 0 ),
          expungeModSeq( 0 ),
          uidnext( 1 ), nextModSeq( 1 ),
          permissions( 0 )
    {}

    bool readOnly;
    SessionInitialiser * initialiser;
    Mailbox * mailbox;
    MessageSet msns;
    MessageSet recent;
    MessageSet expunges;
    int64 expungeModSeq;
    uint uidnext;
    int64 nextModSeq;
    Permissions * permissions;
    MessageSet unannounced;
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
    d->mailbox->addSession( this );
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
    if ( d->mailbox )
        d->mailbox->removeSession( this );
}


/*! Returns true if this Session has updated itself from the database.
*/

bool Session::initialised() const
{
    if ( !d->uidnext )
        return false;
    if ( d->initialiser )
        return false;
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


/*! Returns a MessageSet containing all messages marked "\Recent" in
    this session.
*/

MessageSet Session::recent() const
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


/*! Returns true if this Session needs to refresh the client's
    world view in response to \a type changes.
*/

bool Session::responsesNeeded( ResponseType type ) const
{
    switch ( type ) {
    case New:
        if ( d->unannounced.largest() > d->msns.largest() )
            return true;
        break;
    case Modified:
        if ( !d->unannounced.intersection( d->msns ).isEmpty() )
            return true;
        break;
    case Deleted:
        if ( !d->expunges.isEmpty() )
            return true;
        break;
    }
    return false;
}


/*! Returns false if something's missing before \a type responses can
    be emitted, and true if nothing is known to be missing.
*/

bool Session::responsesReady( ResponseType type ) const
{
    type = type; // to stop the warnings
    if ( d->initialiser )
        return false;
    return true;
}


/*! Records that \a uids has been expunged in the change with sequence
    \a ms, and that the clients should be told about it at the
    earliest possible moment.
*/

void Session::expunge( const MessageSet & uids, int64 ms )
{
    if ( uids.isEmpty() )
        return;
    List<Session>::Iterator i( mailbox()->sessions() );
    while ( i ) {
        i->d->expunges.add( uids );
        i->emitResponses();
        ++i;
    }
    if ( d->expungeModSeq < ms )
        d->expungeModSeq = ms;
}


/*! Emit all the responses that are necessary and possible at this
    time. Carefully ensures that we emit responses in the same order
    every time - New cannot be sent before Modified.
*/

void Session::emitResponses()
{
    bool ok = true;
    if ( ok &&
         responsesNeeded( Deleted ) &&
         responsesPermitted( Deleted ) ) {
        if ( responsesReady( Deleted ) )
            emitResponses( Deleted );
        else
            ok = false;
    }
    if ( ok &&
         responsesNeeded( Modified ) &&
         responsesPermitted( Modified ) ) {
        if ( responsesReady( Modified ) )
            emitResponses( Modified );
        else
            ok = false;
    }
    if ( ok &&
         responsesNeeded( New ) &&
         responsesPermitted( New ) ) {
        if ( responsesReady( New ) )
            emitResponses( New );
        else
            ok = false;
    }
}


/*! Calls emitExpunges(), emitUidnext(), emitModifications() etc. as
    needed and as indicated by \a type. Only sends the desired \a type
    of response. Does not check that responses may legally be sent at
    this point. Updates uidnext() if it announces new messages beyond
    the current uidnext value.
*/

void Session::emitResponses( ResponseType type )
{
    if ( type == Deleted ) {
        emitExpunges();
        d->msns.remove( d->expunges );
        d->expunges.clear();
        if ( d->nextModSeq <= d->expungeModSeq )
            d->nextModSeq = d->expungeModSeq + 1;
        d->expungeModSeq = 0;
    }
    else if ( type == Modified ) {
        if ( responsesReady( Modified ) ) {
            MessageSet known;
            if ( d->uidnext > 1 )
                known.add( 1, d->uidnext - 1 );
            emitModifications();
            d->unannounced.remove( known );
        }
    }
    else { // New
        MessageSet n( d->unannounced );
        if ( !d->msns.isEmpty() ) {
            MessageSet small;
            small.add( 1, d->msns.largest() );
            n.remove( small );
        }
        d->msns.add( n );
        d->unannounced.remove( n );
        emitUidnext();
    }
}


/*! This virtual function is called to notify the client that the
    expunged() messages are expunged. The base implementation does
    nothing.
*/

void Session::emitExpunges()
{
}


/*! Does whatever the protocol requires when a new message is added to
    the mailbox.
*/

void Session::emitUidnext()
{
}


/*! Sets our uidnext value to \a u. Used only by the SessionInitialiser.
*/

void Session::setUidnext( uint u )
{
    d->uidnext = u;
}


/*! Refreshes this session, notifying \a handler when it's done.
*/

void Session::refresh( EventHandler * handler )
{
    if ( !d->initialiser )
        (void)new SessionInitialiser( d->mailbox );
    if ( handler && d->initialiser )
        d->initialiser->addWatcher( handler );
}


class SessionInitialiserData
    : public Garbage
{
public:
    SessionInitialiserData()
        : mailbox( 0 ),
          t( 0 ), recent( 0 ), messages( 0 ), nms( 0 ),
          viewnms( 0 ),
          oldUidnext( 0 ), newUidnext( 0 ),
          state( Again ),
          changeRecent( false )
        {}

    Mailbox * mailbox;
    List<Session> sessions;
    List<EventHandler> watchers;

    Transaction * t;
    Query * recent;
    Query * messages;
    Query * nms;
    int64 viewnms;

    uint oldUidnext;
    uint newUidnext;
    int64 oldModSeq;
    int64 newModSeq;

    enum State { NoTransaction, WaitingForLock, HaveUidnext,
                 ReceivingChanges, Updated, QueriesDone, Again };
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

/*! Constructs an SessionInitialiser for \a mailbox. */

SessionInitialiser::SessionInitialiser( Mailbox * mailbox )
    : EventHandler(), d( new SessionInitialiserData )
{
    d->mailbox = mailbox;
    execute();
}


void SessionInitialiser::execute()
{
    SessionInitialiserData::State state = d->state;
    do {
        state = d->state;
        switch ( d->state ) {
        case SessionInitialiserData::NoTransaction:
            grabLock();
            d->state = SessionInitialiserData::WaitingForLock;
            break;
        case SessionInitialiserData::SessionInitialiserData::WaitingForLock:
            findRecent();
            findUidnext();
            if ( ( !d->recent || d->recent->done() ) &&
                 ( !d->nms || d->nms->done() ) )
                d->state = SessionInitialiserData::HaveUidnext;
            break;
        case SessionInitialiserData::HaveUidnext:
            if ( d->mailbox->view() )
                findViewChanges();
            else
                findMailboxChanges();
            d->state = SessionInitialiserData::ReceivingChanges;
            break;
        case SessionInitialiserData::ReceivingChanges:
            if ( d->mailbox->view() )
                writeViewChanges();
            else
                recordMailboxChanges();
            if ( d->messages->done() )
                d->state = SessionInitialiserData::Updated;
            break;
        case SessionInitialiserData::Updated:
            releaseLock(); // may change d->state
            break;
        case SessionInitialiserData::QueriesDone:
            emitResponses();
            d->state = SessionInitialiserData::Again;
            break;
        case SessionInitialiserData::Again:
            findSessions();
            eliminateGoodSessions();
            restart(); // may change d->state
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


/*! Finds all sessions that may be updated by this
    initialiser. Doesn't lock anything or call
    Session::setSessionInitialiser().
*/

void SessionInitialiser::findSessions()
{
    List<Session>::Iterator i( d->mailbox->sessions() );
    while ( i ) {
        if ( !i->initialised() && !i->sessionInitialiser() ) {
            d->sessions.append( i );
            i->setSessionInitialiser( this );
        }
        ++i;
    }
}


/*! Some sessions have all the information they need to issue their
    responses. This function tries to identify those, make them emit
    their responses and not do any database work on their behalf.

    If this elimiates all sessions, restart() should eliminate the
    SessionInitialiser itself.
*/

void SessionInitialiser::eliminateGoodSessions()
{
    List<Session>::Iterator i( d->sessions );
    while ( i ) {
        List<Session>::Iterator s = i;
        ++i;
        if ( d->mailbox->nextModSeq() <= s->nextModSeq() + 1 ) {
            MessageSet u( s->unannounced() );
            MessageSet unknownNew;
            if ( s->uidnext() < d->mailbox->uidnext() )
                unknownNew.add( s->uidnext(), d->mailbox->uidnext() - 1 );
            bool any = false;
            if ( unknownNew.isEmpty() &&
                 d->mailbox->nextModSeq() == s->nextModSeq() )
                any = true;
            bool allKnown = true;
            while ( !u.isEmpty() && allKnown ) {
                uint uid = u.value( 1 );
                u.remove( uid );
                //Message * m = MessageCache::find( d->mailbox, uid );
                Message * m = 0; // until messagecache exists and works
                if ( uid >= s->uidnext() ) {
                    unknownNew.remove( uid );
                    any = true;
                }
                else if ( !m || !m->modSeq() ) {
                    allKnown = false;
                }
                else if ( m && m->modSeq() == s->nextModSeq() ) {
                    any = true;
                }
            }
            if ( !unknownNew.isEmpty() )
                allKnown = false;
            if ( any && allKnown ) {
                s->setSessionInitialiser( 0 );
                if ( s->nextModSeq() < d->mailbox->nextModSeq() )
                    s->setNextModSeq( d->mailbox->nextModSeq() );
                if ( s->uidnext() < d->mailbox->uidnext() )
                    s->setUidnext( d->mailbox->uidnext() );
                d->sessions.take( s );
            }
        }
    }
}


/*! Initialises various variables, checks that the state is such that
    database work is necessary, and either updates the state so the
    database work will be done, or doesn't.
*/

void SessionInitialiser::restart()
{
    d->newModSeq = d->mailbox->nextModSeq();
    d->newUidnext = d->mailbox->uidnext();
    d->oldModSeq = d->newModSeq;
    d->oldUidnext = d->newUidnext;

    uint uidnext = d->oldUidnext;
    int64 nextModSeq = d->oldModSeq;

    List<Session>::Iterator i( d->mailbox->sessions() );
    while ( i ) {
        if ( i->unannounced().isEmpty() ) {
            if ( i->uidnext() < uidnext )
                uidnext = i->uidnext();
            if ( i->nextModSeq() < nextModSeq )
                nextModSeq = i->nextModSeq();
        }
        if ( i->uidnext() < d->oldUidnext )
            d->oldUidnext = i->uidnext();
        if ( i->nextModSeq() < d->oldModSeq )
            d->oldModSeq = i->nextModSeq();
        ++i;
    }

    // at this point, d->oldUidnext is the oldest uidnext value of all
    // sessions, and uidnext is the oldest value of all _updated_
    // sessions. we only want to work if a session that could emit its
    // changes so far has old data.

    if ( nextModSeq >= d->newModSeq &&
         uidnext >= d->newUidnext &&
         !d->mailbox->view() )
        return;

    if ( d->sessions.isEmpty() )
        return;

    d->state = SessionInitialiserData::NoTransaction;
    d->t = 0;
    d->recent = 0;
    d->messages = 0;
    d->nms = 0;
    d->changeRecent = false;
}


/*! Grabs enough locks on the database that we can update what we need
    to update: Only one session must get the "\recent" flag, and if we
    change view contents, noone else must do so at the same time.
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
    if ( d->mailbox->view() )
        d->changeRecent = false;

    log( "Updating " + fn( d->sessions.count() ) + " session(s) on " +
         d->mailbox->name().ascii() +
         " for modseq [" + fn( d->oldModSeq ) + "," +
         fn( d->newModSeq ) + ">, UID [" + fn( d->oldUidnext ) + "," +
         fn( d->newUidnext ) + ">" );

    if ( d->changeRecent || d->mailbox->view() )
        d->t = new Transaction( this );

    if ( d->changeRecent )
        d->recent = new Query( "select first_recent from mailboxes "
                               "where id=$1 for update", this );
    else if ( highestRecent < d->newUidnext - 1 && !d->mailbox->view() )
        d->recent = new Query( "select first_recent from mailboxes "
                               "where id=$1", this );
    if ( d->recent ) {
        d->recent->bind( 1, d->mailbox->id() );
        submit( d->recent );
    }

    if ( d->mailbox->view() )
        d->nms = new Query( "select mb.uidnext, mb.nextmodseq, "
                            " v.nextmodseq as viewnms, v.source "
                            "from mailboxes mb "
                            "join views v on (v.view=mb.id) "
                            "where mb.id=$1 for update", this );
    else
        d->nms = new Query( "select uidnext, nextmodseq "
                            "from mailboxes where id=$1", this );
    d->nms->bind( 1, d->mailbox->id() );
    submit( d->nms );
}


/*! Commits the transaction, releasing the locks we've held, and
    updates the state so we'll tell the waiting sessions and
    eventhandlers to go on.
*/

void SessionInitialiser::releaseLock()
{
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

    List<Session>::Iterator i( d->sessions );
    while ( i ) {
        if ( i->sessionInitialiser() == this )
            i->setSessionInitialiser( 0 );
        ++i;
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
        return; // could happen if a session violently dies
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


/*! It may be that Mailbox::uidnext() is a little behind the
    times. Since we can retrieve the values from the database at no
    extra cost, this function does so, and updates the Mailbox if
    necessary.
*/

void SessionInitialiser::findUidnext()
{
    if ( !d->nms )
        return;
    Row * r = d->nms->nextRow();
    if ( !r )
        return;

    uint uidnext = r->getInt( "uidnext" );
    int64 nms = r->getBigint( "nextmodseq" );

    if ( d->mailbox->view() )
        d->viewnms = r->getBigint( "viewnms" );

    // XXX I don't like this code, it's icky.

    if ( nms > d->newModSeq && uidnext > d->newUidnext )
        d->mailbox->setUidnextAndNextModSeq( uidnext, nms );
    else if ( nms > d->newModSeq )
        d->mailbox->setUidnext( uidnext );
    else if ( uidnext > d->newUidnext )
        d->mailbox->setNextModSeq( nms );

    if ( uidnext > d->newUidnext )
        d->newUidnext = uidnext;
    if ( nms > d->newModSeq )
        d->newUidnext = nms;
}


/*! Constructs a big complex query to find out what a view's contents
    should be like, which writeViewChanges() can use to update the
    view_messages table and the Sessions. Takes care to make the query
    as simple as possible, so it only looks at modseq if necessary.

    The generated query is big, complex and invariant. Perhaps we
    should try to make a PreparedStatement. Not sure how. There's
    nowhere natural to put it.
*/

void SessionInitialiser::findViewChanges()
{
    Selector * sel = new Selector;
    sel->add( Selector::fromString( d->mailbox->selector() ) );

    // if not dynamic, uidnext changed by >0 and modsec by <= 1,, we
    // can add UID logic to _both_ the mm and s selects, and it'll do
    // the right thing.

    if ( d->viewnms )
        sel->add( new Selector( Selector::Modseq, Selector::Larger,
                                d->viewnms ) );
    sel->simplify();


    d->messages = sel->query( 0, d->mailbox->source(), 0, this );
    uint vid = sel->placeHolder();
    d->messages->bind( vid, d->mailbox->id() );

    String s( "select m.id, "
              "v.uid as vuid, v.modseq as vmodseq, "
              "s.uid as suid, s.modseq as smodseq, "
              "s.message as smessage, s.idate as sidate "
              "from messages m "
              "left join mailbox_messages v "
              " on (m.id=v.message and v.mailbox=$" + fn( vid ) + ") "
              "left join (" + d->messages->string() + ") s "
              " on m.id=s.message "
              "where ((s.uid is not null and v.uid is null)"
              "    or (s.uid is null and v.uid is not null)"
              "    or s.modseq>=$" + fn( d->viewnms ) + ") "
              "order by v.uid, s.uid, m.id" );
    d->messages->setString( s );
    submit( d->messages );
}


/*! Processes the query results from the Query generated by
    findViewChanges(), adds to and/or removes from the view_messages
    table and the in-RAM Session object as a result, and updates the
    view so the next SessionInitialiser will not have to consider the
    same messages.
*/

void SessionInitialiser::writeViewChanges()
{
    if ( !d->messages->done() )
        return;
    MessageSet removeInDb;
    Query * add = 0;
    Query * remove = 0;
    Row * r = 0;
    while ( (r=d->messages->nextRow()) != 0 ) {
        uint vuid = 0;
        if ( !r->isNull( "vuid" ) )
            vuid = r->getInt( "vuid" );

        bool matched = true;
        if ( r->isNull( "suid" ) )
            matched = false;

        if ( vuid && !matched ) {
            // if it left the search result but still is in the db, we
            // want to remove it from the db
            if ( !remove )
                remove = new Query( "copy deleted_messages "
                                    "(mailbox,uid,message,modseq,"
                                    " deleted_by,reason) "
                                    "from stdin with binary", 0 );
            remove->bind( 1, d->mailbox->id(), Query::Binary );
            remove->bind( 2, vuid, Query::Binary );
            remove->bind( 3, r->getInt( "id" ), Query::Binary );
            remove->bind( 4, r->getInt( "vmodseq" ), Query::Binary );
            remove->bindNull( 5 );
            remove->bind( 6, String( "left view" ), Query::Binary );
            remove->submitLine();
            removeInDb.add( vuid );
        }
        else if ( matched && !vuid ) {
            // if it entered the search result and isn't in the db, we
            // want to add it to the db
            if ( !add )
                add = new Query ( "copy mailbox_messages "
                                  "(mailbox,uid,message,idate,modseq) "
                                  "from stdin with binary", 0 );
            vuid = d->newUidnext;
            d->newUidnext++;
            add->bind( 1, d->mailbox->id(), Query::Binary );
            add->bind( 2, vuid, Query::Binary );
            add->bind( 3, r->getInt( "smessage" ), Query::Binary );
            add->bind( 4, r->getInt( "sidate" ), Query::Binary );
            add->bind( 5, d->newModSeq, Query::Binary );
            add->submitLine();
            addToSessions( vuid, d->newModSeq );
        }
        else if ( matched && vuid ) {
            // if it is in the search results and also in the db, then
            // it's new to the session or changed in the session.
            addToSessions( vuid, r->getBigint( "vmodseq" ) );
        }
    }

    if ( add ) {
        submit( add );
        Query * q = new Query( "update mailboxes "
                               "set uidnext=$1,nextmodseq=$2 "
                               "where id=$3", 0 );
        q->bind( 1, d->newUidnext );
        q->bind( 2, d->newModSeq + 1 );
        q->bind( 3, d->mailbox->id() );
        submit( q );
        d->mailbox->setUidnextAndNextModSeq( d->newUidnext,
                                             d->newModSeq + 1 );
    }

    if ( remove ) {
        submit( remove );
        List<Session>::Iterator i( d->sessions );
        while ( i ) {
            Session * s = i;
            ++i;
            s->expunge( removeInDb, 0 ); // expunge does not consume a modseq
        }
    }
}


/*! Issues a query to find new and changed messages in the
    mailbox. Does not look for expunged messages: We trust the ocd to
    do that. Perhaps this should join on deleted_messages and find the
    expunged messages?
*/

void SessionInitialiser::findMailboxChanges()
{
    bool initialising = false;
    if ( d->oldUidnext <= 1 )
        initialising = true;
    String msgs = "select mm.uid, mm.modseq from mailbox_messages mm "
                  "where mm.mailbox=$1 and mm.uid<$2";
    if ( initialising ) // largest-first to please messageset
        msgs.append( " order by mm.uid desc" );

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


/*! Persuades each Session to emit its responses and tells each
    handler added with addWatcher() to go on working.
*/

void SessionInitialiser::emitResponses()
{
    List<Session>::Iterator s( d->sessions );
    while ( s ) {
        if ( s->nextModSeq() < d->mailbox->nextModSeq() )
            s->setNextModSeq( d->mailbox->nextModSeq() );
        if ( s->uidnext() < d->mailbox->uidnext() )
            s->setUidnext( d->mailbox->uidnext() );
        s->setSessionInitialiser( 0 );

        s->emitResponses();

        ++s;
    }
    d->sessions.clear();

    List<EventHandler>::Iterator it( d->watchers );
    while ( it ) {
        EventHandler * e = it;
        ++it;
        e->execute();
    }
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
    emitExpunges().
*/

void Session::clearExpunged()
{
    d->msns.remove( d->expunges );
    d->expunges.clear();
}


/*! Records that \a e should be notified when the initialiser has
    finished its work.
*/

void SessionInitialiser::addWatcher( EventHandler * e )
{
    if ( e && d->watchers.find( e ) == d->watchers.end() )
        d->watchers.append( e );
}


/*! The SessionInitialiser calls this when it's creating itself (thus,
    \a s refers to itself), so that initialised() can return false
    until the SessionInitialiser is removed again with
    setSessionInitialiser( 0 ). Noone else should ever call it.
*/

void Session::setSessionInitialiser( class SessionInitialiser * s )
{
    d->initialiser = s;
}


/*! Returns a pointer to the SessionInitialiser that works on this
    Session at the moment, 0 usually.
*/

SessionInitialiser * Session::sessionInitialiser() const
{
    return d->initialiser;
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


/*! Returns true if this session can notify its client of a \a type
    events.
*/

bool Session::responsesPermitted( ResponseType type ) const
{
    type = type; // for the warnings
    return true;
}


/*! This virtual function emits whatever data is necessary and
    appropriate to inform the client of unannounced() modifications.
    The default implementation does nothing.
*/

void Session::emitModifications()
{
}


/*! Returns whatever has been set using addUnannounced() and not
    announced by emitResponses().
*/

MessageSet Session::unannounced() const
{
    return d->unannounced;
}


/*! Records that the messages in \a s have been added to the mailbox
    or changed, and should be announced to the client and if necessary
    added to the session.
*/

void Session::addUnannounced( const MessageSet & s )
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
