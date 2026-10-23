// Copyright 2025 The Archiveopteryx Developers <info@aox.org>

#include "mover.h"

#include "map.h"
#include "dict.h"
#include "flag.h"
#include "query.h"
#include "timer.h"
#include "address.h"
#include "message.h"
#include "ustring.h"
#include "mailbox.h"
#include "bodypart.h"
#include "datefield.h"
#include "mimefields.h"
#include "messagecache.h"
#include "helperrowcreator.h"
#include "addressfield.h"
#include "transaction.h"
#include "annotation.h"
#include "postgres.h"
#include "session.h"
#include "scope.h"
#include "graph.h"
#include "html.h"
#include "user.h"
#include "md5.h"
#include "utf.h"
#include "log.h"
#include "dsn.h"


class MoverData
    : public Garbage
{
public:
    MoverData()
        : owner( 0 ),
          user( 0 ),
          transaction( 0 ),
          mailboxes( new List<MoverData::Mailbox>() ),
          lock( 0 ), messages( 0 ),
          to( 0 ), from( 0 ),
          middle( 0 ),
          expunge( false )

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
                nextmodseq = r->getInt( "nextmodseq" );
                flag = r->getEString( "flag" );
            }

        EString flag;
        uint id;
        int uidnext;
        int nextmodseq;
    };

    void enqueueInsertions( const IntegerSet & mailboxIds );
    void enqueueRemoves( const IntegerSet & mailboxIds );
    void enqueueRemovesFromAllmail();

    EventHandler * owner;
    User * user;
    Transaction * transaction;
    List<MoverData::Mailbox> * mailboxes;
    Query * lock;
    Query * messages;
    ::Mailbox * to;
    ::Mailbox * from;
    IntegerSet sourceUids;
    IntegerSet messageIds;
    Query * middle;
    bool expunge;
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
*/

/*! Constructs a Mover that moves the messages with \a uids from
    mailbox \a from to mailbox \a to using a subtransaction of \a
    within, updating the special-use mailboxes of \a user as necessary.

    \a messages are the UIDs of the messages in \a * from.

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
    d->from = from;
    d->sourceUids = uids;
    d->middle = middle;
    d->expunge = expunge;

    d->lock = new Query(
        EString() +
        "select id,uidnext,nextmodseq,flag from mailboxes "
        "where id=$1 or id=$2 or id in ("
        "select mm1.id from mailbox_messages mm1 "
        "join mailbox_messages mm2 using (message) "
        "where mm2.id=$1 and mm2.uid=any($3) "
        ") or id in ("
        "select mailbox from mailboxes "
        "where owner=$4 and flag is not null"
        ") order by id for update" +
        (patient ? "" : " nowait"),
        this );
    d->lock->bind( 1, d->from->id() );
    d->lock->bind( 2, d->to->id() );
    d->lock->bind( 3, uids );
    d->lock->bind( 4, d->to->owner() );
    d->transaction->enqueue( d->lock );

    d->messages = new Query( "select message from mailbox_messages "
                             "where mailbox=$1 and uid=any($2)",
                             this );
    d->messages->bind( 1, d->from->id() );
    d->messages->bind( 2, uids );
    d->transaction->enqueue( d->messages );

    d->transaction->execute();
}



void Mover::execute()
{
    while ( d->lock->hasResults() )
        d->mailboxes->append( new MoverData::Mailbox( d->lock->nextRow() ) );

    while ( d->messages->hasResults() )
        d->messageIds.add( d->messages->nextRow()->getInt( "message" ) );

    if ( !d->messages->done() )
        return;

    if ( !d->transaction )
        return;

    // find the complete sets of mailboxes where the messages are
    // inserted and removed.
    IntegerSet removeFrom;
    IntegerSet addTo;

    if ( d->to->flag() == "\\junk" ) {
         List<MoverData::Mailbox>::Iterator it( d->mailboxes );
         while ( it ) {
             if ( it->id != d->to->id() )
                 removeFrom.add( it->id );
             ++it;
         }
    }
    else if ( d->to->flag() == "\\trash" ) {
         List<MoverData::Mailbox>::Iterator it( d->mailboxes );
         while ( it ) {
             if ( it->flag == "\\junk" )
                 removeFrom.add( it->id );
             ++it;
         }
    }
    else if ( d->from->flag() == "\\junk" ||
              d->from->flag() == "\\trash" ) {
        List<MoverData::Mailbox>::Iterator it( d->mailboxes );
        while ( it ) {
            if ( it->flag == "\\junk" ||
                 it->flag == "\\trash" )
                removeFrom.add( it->id );
            else if ( it->flag == "\\all" )
                addTo.add( it->id );
            ++it;
        }
    }
    // ... and at the end, pay a little attention to the caller's wishes
    addTo.add( d->to->id() );
    if ( d->expunge && d->from->flag() != "\\all" )
        removeFrom.add( d->from->id() );

    // we don't bother removing from a mailbox to which we'll add anyway
    removeFrom.remove( addTo );

    d->enqueueInsertions( addTo );
    if ( d->middle )
        d->transaction->enqueue( d->middle );
    d->enqueueRemoves( removeFrom );
    d->enqueueRemovesFromAllmail();

    Mailbox::refreshMailboxes( d->transaction );
    d->transaction->commit();
    d->owner->execute();
    d->transaction = 0;
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

            bool duplicate = ( from == to && to->flag() != "\\all" );

            q = new Query( EString("") +
                           "insert into mailbox_messages "
                           "(mailbox, uid, message, modseq, seen) "
                           "select $1, nextval('s'), mm1.message, $2, "
                           "mm1.seen "
                           "from mailbox_messages mm1 " +
                           (duplicate
                            ? ""
                            : "left join mailbox_messages mm2 on"
                            "(mm1.message=mm2.message and mm2.mailbox=$1) " ) +
                           "where mm1.mailbox=$3 and mm1.uid=any($4) " +
                           (duplicate
                            ? ""
                            : "and mm2.uid is null ") +
                           "order by uid", 0 );
            q->bind( 1, it->id );
            q->bind( 2, it->nextmodseq );
            q->bind( 3, from->id() );
            q->bind( 4, sourceUids );
            transaction->enqueue( q );

            // this occasionally increases nextmodseq for no reason...
            q = new Query( "update mailboxes "
                           "set uidnext=nextval('s'), nextmodseq=$1 "
                           "where id=$2",
                           0 );
            q->bind( 1, it->nextmodseq + 1 );
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
                "insert into deleted_messages "
                "(mailbox,uid,message,modseq,deleted_by,reason) "
                "select $1, uid, message, $3, $2,"
                " 'moved to mailbox '||$4 "
                "from mailbox_messages mm "
                "where mailbox=$1 and mm.uid=any($5)", 0 );
            q->bind( 1, from->id() );
            q->bind( 2, user->id() );
            q->bind( 3, it->nextmodseq );
            q->bind( 4, to->name() );
            q->bind( 5, sourceUids );
            transaction->enqueue( q );
            q = new Query( "update mailboxes "
                           "set nextmodseq=$1 "
                           "where id=$2",
                           0 );
            q->bind( 1, it->nextmodseq + 1 );
            q->bind( 2, it->id );
            transaction->enqueue( q );
        }
        ++it;
    }
}


void MoverData::enqueueRemovesFromAllmail() {
    IntegerSet all;
    List<MoverData::Mailbox>::Iterator it( mailboxes );
    while ( it ) {
        if ( it->flag == "\\all" )
            all.add( it->id );
        ++it;
    }
    if ( all.isEmpty() )
        return;

    // some special-use mailboxes should cause the message to be in allmail:
    EStringList extantMessageFlags;
    extantMessageFlags.append("\\archive");

    Query * q = new Query(
        "insert into deleted_messages "
        "(mailbox,uid,message,modseq,deleted_by,reason) "
        "select $1, mm.uid, message, $3, $2, 'moved to trash' "
        "from mailbox_messages mm "
        "join mailboxes mb on (mm.mailbox=mb.id) "
        "where mm.mailbox=any($1) and mm.message=any($4) and mm.message not in "
        "(select rm.message"
        " from mailbox_messages rm"
        " join mailboxes rmb on (rm.mailbox=rmb.id)"
        " where rmb.owner=mb.owner and rm.message=any($4)"
        " and (rmb.flag is null or rmb.flag=any($5)))", 0 );
    q->bind( 1, all );
    q->bind( 2, user->id() );
    q->bind( 3, it->nextmodseq );
    q->bind( 4, messageIds );
    q->bind( 5, extantMessageFlags );
    transaction->enqueue( q );
    q = new Query( "update mailboxes "
                   "set nextmodseq=$1 "
                   "where id=$2",
                   0 );
    q->bind( 1, all.nextmodseq + 1 );
    q->bind( 2, all.id );
    transaction->enqueue( q );
}
