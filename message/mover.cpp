// Copyright 2025 The Archiveopteryx Developers <info@aox.org>

#include "mover.h"

#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "integerset.h"
#include "estringlist.h"
#include "transaction.h"


class MoverData
    : public Garbage
{
public:
    MoverData()
        : owner( 0 ),
          user( 0 ),
          transaction( 0 ),
          mailboxes( new List<MoverData::Mailbox>() ),
          lock( 0 ), findMs( 0 ), messages( 0 ), report( 0 ),
          to( 0 ), from( 0 ), named( 0 ),
          allMail( 0 ), trash( 0 ),
          middle( 0 ),
          ms( 0 ),
          scopeOwner( 0 ),
          expunge( false ), done( false )

        {
        }

    class Mailbox
        : public Garbage
    {
    public:
        Mailbox( Row * r )
            {
                id = r->getInt( "id" );
                uidnext = r->getInt( "uidnext" );
                owner = 0;
                if ( !r->isNull( "owner" ) )
                    owner = r->getInt( "owner" );
                if ( !r->isNull( "flag" ) )
                    flag = r->getEString( "flag" );
            }

        EString flag;
        uint id;
        uint uidnext;
        uint owner;
    };

    void enqueueInsertions( const IntegerSet & mailboxIds );
    void enqueueRemoves( const IntegerSet & mailboxIds );
    void enqueueRemovesFromAllmail();
    EString reason() const;

    EventHandler * owner;
    User * user;
    Transaction * transaction;
    List<MoverData::Mailbox> * mailboxes;
    Query * lock;
    Query * findMs;
    Query * messages;
    Query * report;
    ::Mailbox * to;
    ::Mailbox * from;
    ::Mailbox * named;
    ::Mailbox * allMail;
    ::Mailbox * trash;
    IntegerSet sourceUids;
    IntegerSet messageIds;
    Query * middle;
    int64 ms;
    uint scopeOwner;
    bool expunge;
    bool done;
};



/*! \class Mover

    The Mover class moves or copies a set of messages from one mailbox
    to another, taking care to maintain three invariants.

    There are up to three special mailboxes. All other mailboxes are
    called regular. The three possible special mailboxes are "all
    mail", "trash" and "junk".

    If the target mailbox of a move is "junk", then Mover makes sure
    that the messages are also removed from "all mail", all regular
    mailboxes and also "trash".

    If the target mailbox of a move is "trash", then Mover makes sure
    that the messages are also removed from "junk". If this leaves the
    message in only "trash" and "all mail", then it's also removed
    from "all mail".

    If the target mailbox's owner has an "all mail" mailbox, then
    Mover makes sure that afterwards, if and only if a message exists
    in a regular mailbox, then it also is in "all mail".

    If the source mailbox is either either "junk" or "trash" and the
    target mailbox is neither, then Mover makes sure that the messages
    are also removed from both "junk" and "trash".

    Mover also handles expunging, so that no caller has to know about
    the special mailboxes. A caller that wants to expunge passes a
    null target and true for expunge, and Mover works out whether that
    means deleting the messages or moving them to trash.

    The sweeps only affect mailboxes owned by whoever owns the target:
    moving a message to my junk mailbox cannot remove it from a shared
    mailbox, or from yours.
*/


static Mailbox * flagged( Mailbox * m, const EString & flag )
{
    if ( !m )
        return 0;
    if ( m->id() && !m->deleted() && m->flag().lower() == flag )
        return m;
    List<Mailbox> * c = m->children();
    if ( !c )
        return 0;
    List<Mailbox>::Iterator i( c );
    while ( i ) {
        Mailbox * r = flagged( i, flag );
        if ( r )
            return r;
        ++i;
    }
    return 0;
}


/*! Returns the home mailbox of whoever owns \a m, ie. the ancestor
    that is a user's root, or a null pointer if \a m is shared.
*/

Mailbox * Mover::homeOf( Mailbox * m )
{
    while ( m && !m->isHome() )
        m = m->parent();
    if ( m && m->owner() )
        return m;
    return 0;
}


/*! Returns the mailbox with RFC6154 attribute \a flag belonging to
    the owner of \a context, or a null pointer if there is none.

    The mailbox tree holds the attributes already, so this costs
    nothing but a short walk. The answer can be a moment out of date,
    if another process has just created a special-use mailbox, and
    then a message misses out on e.g. all mail until aox update
    database next runs.
*/

Mailbox * Mover::specialUse( Mailbox * context, const EString & flag )
{
    Mailbox * home = homeOf( context );
    if ( !home )
        return 0;
    return flagged( home, flag );
}


/*! Adds to the all mail mailbox \a name every message \a owner has in
    a regular mailbox and which is not in all mail already, using
    modseq \a ms, as part of transaction \a t, and returns the query
    that does the inserting, so that the caller can see how many
    messages it added. At most \a limit messages are added, unless \a
    limit is 0, which means all of them.

    The mailbox is addressed by name rather than by id, because the
    caller may just have created it in \a t and not know its id yet.
*/

Query * Mover::fillAllMail( Transaction * t, const UString & name,
                            uint owner, int64 ms, uint limit )
{
    EStringList extantMessageFlags;
    extantMessageFlags.append( "\\archive" );

    Query * q = new Query(
        EString( "insert into mailbox_messages "
                 "(mailbox, uid, message, modseq) " ) +
        "select mb.id,"
        " mb.uidnext + row_number() over (order by m.message) - 1,"
        " m.message, $3 "
        "from (select id, uidnext from mailboxes where name=$1) mb,"
        " (select distinct mm.message from mailbox_messages mm "
        "join mailboxes smb on (mm.mailbox=smb.id) "
        "where smb.owner=$2 and not smb.deleted and smb.name<>$1 "
        "and (smb.flag is null or lower(smb.flag)=any($4)) "
        "and not exists (select 1 from mailbox_messages am "
        "join mailboxes amb on (am.mailbox=amb.id) "
        "where amb.name=$1 and am.message=mm.message) "
        "order by mm.message" +
        ( limit ? " limit " + fn( limit ) : EString() ) + ") m", 0 );
    q->bind( 1, name );
    q->bind( 2, owner );
    q->bind( 3, ms );
    q->bind( 4, extantMessageFlags );
    t->enqueue( q );
    Query * inserter = q;

    // uidnext and first_recent are read back from what we just
    // inserted, so that this works the same for a mailbox that was
    // empty and for one being filled in a second pass.
    q = new Query( "update mailboxes set "
                   "uidnext=1+coalesce((select max(uid) "
                   "from mailbox_messages where mailbox=mailboxes.id),0),"
                   "first_recent=1+coalesce((select max(uid) "
                   "from mailbox_messages where mailbox=mailboxes.id),0),"
                   "nextmodseq=$2 "
                   "where name=$1", 0 );
    q->bind( 1, name );
    q->bind( 2, ms + 1 );
    t->enqueue( q );

    return inserter;
}


/*! Constructs a Mover that moves the messages with \a uids from
    mailbox \a from to mailbox \a to using a subtransaction of \a
    within, updating the special-use mailboxes of \a user as necessary.

    \a messages are the UIDs of the messages in \a * from.

    If \a to is null and \a expunge is true, the messages are to go
    away: that means deleting them if \a from is trash (or if the
    owner has no trash mailbox), deleting them from every mailbox the
    owner has if \a from is all mail, and moving them to trash
    otherwise.

    If \a expunge is true, the caller generally expects that the
    messages are removed from \a from after the subtransaction, and if
    it's false, the caller expects the messages to stay.

    If \a patient is true, the caller is willing to wait for locks to
    be acquired, while if it is false, the caller prefers to abort the
    transaction rather than wait for a lock.

    If \a middle is supplied, the query will be enqueued while the
    messages exist in both \a from and \a to.
*/

Mover::Mover( Transaction * within,
              User * user,
              Mailbox * from, Mailbox * to,
              const IntegerSet & uids,
              Query * middle,
              bool expunge, bool patient )
    : d( new MoverData )
{
    d->owner = within->owner();
    d->user = user;
    d->transaction = within->subTransaction( this );
    d->to = to;
    d->named = to;
    d->from = from;
    d->sourceUids = uids;
    d->middle = middle;
    d->expunge = expunge;

    // The invariants are about one user's mailboxes, so we need to
    // know whose. Usually source and target have the same owner; if
    // the target is a shared mailbox, the source owner's invariants
    // are still the ones that have to hold.
    Mailbox * context = to ? to : from;
    Mailbox * home = homeOf( context );
    if ( !home ) {
        context = from;
        home = homeOf( context );
    }
    if ( home )
        d->scopeOwner = home->owner();
    d->allMail = specialUse( context, "\\all" );
    d->trash = specialUse( context, "\\trash" );
    bool special = d->allMail || d->trash ||
                   specialUse( context, "\\junk" );

    if ( !to && expunge && d->trash &&
         from != d->trash && from != d->allMail )
        d->to = d->trash;

    IntegerSet ids;
    ids.add( from->id() );
    if ( d->to )
        ids.add( d->to->id() );

    EString q( "select id,uidnext,owner,flag from mailboxes "
               "where id=any($1)" );
    if ( special )
        // The owner's own flagged mailboxes, and the owner's mailboxes
        // that hold any of these messages: those are the only ones
        // the invariants can make us touch.
        q.append( " or (owner=$2 and (flag is not null or id in ("
                  "select mm1.mailbox from mailbox_messages mm1 "
                  "where mm1.message in ("
                  "select message from mailbox_messages "
                  "where mailbox=$3 and uid=any($4)))))" );
    q.append( " order by id for update" );
    if ( !patient )
        q.append( " nowait" );

    d->lock = new Query( q, this );
    d->lock->bind( 1, ids );
    if ( special ) {
        d->lock->bind( 2, d->scopeOwner );
        d->lock->bind( 3, d->from->id() );
        d->lock->bind( 4, uids );
    }
    d->transaction->enqueue( d->lock );

    if ( special ) {
        // Only the sweeps need to know which messages these uids are,
        // and they only happen when the owner has a special mailbox.
        // Asking anyway would cost a row per uid on every COPY.
        d->messages = new Query( "select message from mailbox_messages "
                                 "where mailbox=$1 and uid=any($2)",
                                 this );
        d->messages->bind( 1, d->from->id() );
        d->messages->bind( 2, uids );
        d->transaction->enqueue( d->messages );
    }

    // One modseq serves the whole move, in every mailbox it touches.
    // It has to be allocated after the lock: nextval() in the target
    // list of a locking select is evaluated a second time if the lock
    // has to wait, and allocating afterwards keeps the values in lock
    // order, which per-mailbox monotonicity needs.
    d->findMs = new Query( "select nextval('nextmodseq') as nextmodseq",
                           this );
    d->transaction->enqueue( d->findMs );

    d->transaction->execute();
}


/*! Returns true once the Mover has enqueued all its work and
    committed its subtransaction, and false until then. A caller that
    commits the enclosing transaction has to wait for this.
*/

bool Mover::done() const
{
    return d->done;
}


/*! Returns a query whose rows map the source uid of each copied
    message to the uid it received in the target mailbox (columns uid
    and nuid), or a null pointer if the caller did not name a target
    mailbox. COPY needs this for COPYUID.
*/

Query * Mover::report() const
{
    return d->report;
}


/*! Returns the modseq this move uses in every mailbox it touches, or
    0 before it has been allocated. A caller that changes the same
    mailboxes in the same transaction should use the same modseq.
*/

int64 Mover::modseq() const
{
    return d->ms;
}


void Mover::execute()
{
    while ( d->lock->hasResults() )
        d->mailboxes->append( new MoverData::Mailbox( d->lock->nextRow() ) );

    while ( d->messages && d->messages->hasResults() )
        d->messageIds.add( d->messages->nextRow()->getInt( "message" ) );

    if ( d->findMs->hasResults() )
        d->ms = d->findMs->nextRow()->getBigint( "nextmodseq" );

    if ( !d->findMs->done() )
        return;

    if ( !d->transaction )
        return;

    // find the complete sets of mailboxes where the messages are
    // inserted and removed.
    IntegerSet removeFrom;
    IntegerSet addTo;

    EString toFlag;
    if ( d->to )
        toFlag = d->to->flag().lower();
    EString fromFlag = d->from->flag().lower();

    List<MoverData::Mailbox>::Iterator it( d->mailboxes );
    while ( it ) {
        bool ours = ( it->owner && it->owner == d->scopeOwner );
        EString itFlag = it->flag.lower();
        if ( toFlag == "\\junk" ) {
            if ( ours && it->id != d->to->id() )
                removeFrom.add( it->id );
        }
        else if ( toFlag == "\\trash" ) {
            if ( ours && itFlag == "\\junk" )
                removeFrom.add( it->id );
        }
        else if ( fromFlag == "\\junk" || fromFlag == "\\trash" ) {
            if ( ours && ( itFlag == "\\junk" || itFlag == "\\trash" ) )
                removeFrom.add( it->id );
            else if ( itFlag == "\\all" )
                addTo.add( it->id );
        }
        // An expunge in all mail is the one operation that means the
        // message is to be gone, not merely moved out of sight.
        if ( d->expunge && fromFlag == "\\all" && ours )
            removeFrom.add( it->id );
        ++it;
    }
    // ... and at the end, pay a little attention to the caller's wishes
    if ( d->to )
        addTo.add( d->to->id() );
    if ( d->expunge && fromFlag != "\\all" )
        removeFrom.add( d->from->id() );

    // we don't bother removing from a mailbox to which we'll add anyway
    removeFrom.remove( addTo );

    // ... except the source of a move, which may also be the target:
    // moving to the selected mailbox is legal, the copies have new
    // uids, and RFC9051 6.4.8 says each message has to end up moved
    // or unaffected, never in both places at once.
    if ( d->expunge && fromFlag != "\\all" )
        removeFrom.add( d->from->id() );

    d->enqueueInsertions( addTo );
    if ( d->middle )
        d->transaction->enqueue( d->middle );
    d->enqueueRemoves( removeFrom );
    if ( d->allMail )
        d->enqueueRemovesFromAllmail();

    d->transaction->commit();
    d->transaction = 0;
    d->done = true;
    d->owner->execute();
}


EString MoverData::reason() const
{
    if ( to )
        return "moved to mailbox " + to->name().utf8();
    return "expunged";
}


void MoverData::enqueueInsertions( const IntegerSet & mailboxIds ) {
    List<MoverData::Mailbox>::Iterator it( mailboxes );
    while ( it ) {
        if ( mailboxIds.contains( it->id ) ) {
            Query * q;
            q = new Query( "create temporary sequence s start " +
                           fn( it->uidnext ),
                           0 );
            transaction->enqueue( q );

            if ( named && it->id == named->id() ) {
                // The mailbox the caller named gets a copy of every
                // message, as IMAP says, and the caller gets to know
                // which uid each copy received.
                transaction->enqueue(
                    new Query( "create temporary table t ("
                               "uid integer, message integer, nuid integer)",
                               0 ) );

                q = new Query( "insert into t (uid, message, nuid) "
                               "select uid, message, nextval('s') "
                               "from mailbox_messages "
                               "where mailbox=$1 and uid=any($2) "
                               "order by uid", 0 );
                q->bind( 1, from->id() );
                q->bind( 2, sourceUids );
                transaction->enqueue( q );

                q = new Query( "insert into mailbox_messages "
                               "(mailbox, uid, message, modseq) "
                               "select $1, nuid, message, $2 from t", 0 );
                q->bind( 1, it->id );
                q->bind( 2, ms );
                transaction->enqueue( q );

                q = new Query( "insert into annotations "
                               "(mailbox, uid, owner, name, value) "
                               "select $1, t.nuid, a.owner, a.name, a.value "
                               "from annotations a join t using (uid) "
                               "where a.mailbox=$3 "
                               "and (a.owner is null or a.owner=$2)", 0 );
                q->bind( 1, it->id );
                if ( user )
                    q->bind( 2, user->id() );
                else
                    q->bindNull( 2 );
                q->bind( 3, from->id() );
                transaction->enqueue( q );

                // the owner, not us: it is the caller that waits for
                // these rows, and nobody else would wake it
                report = new Query( "select uid, nuid from t", owner );
                transaction->enqueue( report );

                transaction->enqueue( new Query( "drop table t", 0 ) );
            }
            else {
                // The mailboxes the invariants bring in get one copy
                // of each message and no more, however many copies
                // the source holds.
                q = new Query( "insert into mailbox_messages "
                               "(mailbox, uid, message, modseq) "
                               "select $1, nextval('s'), m.message, $2 "
                               "from (select distinct mm1.message "
                               "from mailbox_messages mm1 "
                               "left join mailbox_messages mm2 on "
                               "(mm1.message=mm2.message and mm2.mailbox=$1) "
                               "where mm1.mailbox=$3 and mm1.uid=any($4) "
                               "and mm2.uid is null) m", 0 );
                q->bind( 1, it->id );
                q->bind( 2, ms );
                q->bind( 3, from->id() );
                q->bind( 4, sourceUids );
                transaction->enqueue( q );
            }

            // The sequence was created at uidnext, so if nothing was
            // inserted, this leaves uidnext alone.
            q = new Query( "update mailboxes "
                           "set uidnext=nextval('s'), nextmodseq=$1 "
                           "where id=$2",
                           0 );
            q->bind( 1, ms + 1 );
            q->bind( 2, it->id );
            transaction->enqueue( q );

            transaction->enqueue( new Query( "drop sequence s", 0 ) );
        }
        ++it;
    }
}


void MoverData::enqueueRemoves( const IntegerSet & mailboxIds ) {
    List<MoverData::Mailbox>::Iterator it( mailboxes );
    while ( it ) {
        if ( mailboxIds.contains( it->id ) ) {
            Query * q = new Query(
                EString( "insert into deleted_messages "
                         "(mailbox,uid,message,modseq,deleted_by,reason) "
                         "select $1, uid, message, $3, $2, $4 "
                         "from mailbox_messages mm "
                         "where mailbox=$1 and " ) +
                // The source mailbox may hold two copies of one
                // message, and then only the copy the caller named is
                // to go. Elsewhere we have no uids, only messages.
                ( it->id == from->id()
                  ? "mm.uid=any($5)"
                  : "mm.message=any($5)" ), 0 );
            q->bind( 1, it->id );
            if ( user )
                q->bind( 2, user->id() );
            else
                q->bindNull( 2 );
            q->bind( 3, ms );
            q->bind( 4, reason() );
            if ( it->id == from->id() )
                q->bind( 5, sourceUids );
            else
                q->bind( 5, messageIds );
            transaction->enqueue( q );
            q = new Query( "update mailboxes "
                           "set nextmodseq=$1 "
                           "where id=$2",
                           0 );
            q->bind( 1, ms + 1 );
            q->bind( 2, it->id );
            transaction->enqueue( q );
        }
        ++it;
    }
}


void MoverData::enqueueRemovesFromAllmail() {
    // Some special-use mailboxes keep a message in all mail, the rest
    // do not, so a message that is now only in e.g. trash leaves.
    EStringList extantMessageFlags;
    extantMessageFlags.append( "\\archive" );

    List<MoverData::Mailbox>::Iterator it( mailboxes );
    while ( it ) {
        if ( it->flag.lower() == "\\all" ) {
            // This runs after the removes above, and the trigger on
            // deleted_messages has already taken those rows out of
            // mailbox_messages, so the subquery sees the end state.
            Query * q = new Query(
                "insert into deleted_messages "
                "(mailbox,uid,message,modseq,deleted_by,reason) "
                "select $1, mm.uid, mm.message, $3, $2,"
                " 'no longer in any regular mailbox' "
                "from mailbox_messages mm "
                "where mm.mailbox=$1 and mm.message=any($4) "
                "and not exists (select 1 from mailbox_messages rm "
                "join mailboxes rmb on (rm.mailbox=rmb.id) "
                "where rm.message=mm.message and rmb.owner=$5 "
                "and (rmb.flag is null or lower(rmb.flag)=any($6)))", 0 );
            q->bind( 1, it->id );
            if ( user )
                q->bind( 2, user->id() );
            else
                q->bindNull( 2 );
            q->bind( 3, ms );
            q->bind( 4, messageIds );
            q->bind( 5, scopeOwner );
            q->bind( 6, extantMessageFlags );
            transaction->enqueue( q );
            q = new Query( "update mailboxes "
                           "set nextmodseq=$1 "
                           "where id=$2",
                           0 );
            q->bind( 1, ms + 1 );
            q->bind( 2, it->id );
            transaction->enqueue( q );
        }
        ++it;
    }
}
