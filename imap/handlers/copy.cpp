// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "copy.h"

#include "imapsession.h"
#include "transaction.h"
#include "integerset.h"
#include "mailbox.h"
#include "query.h"
#include "user.h"


class CopyData
    : public Garbage
{
public:
    CopyData() :
        uid( false ), move( false ),
        mailbox( 0 ), transaction( 0 ),
        findUid( 0 ),
        report( 0 )
    {}
    bool uid;
    bool move;
    IntegerSet set;
    Mailbox * mailbox;
    Transaction * transaction;
    Query * findUid;
    Query * report;
    uint toUid;
    int64 toMs;
    int64 fromMs;
};


/*! \class Copy copy.h

    The Copy class implements the IMAP COPY command (RFC 3501 section
    6.4.7), as extended by RFC 4315.

    Copy copies all elements of a message, including such things as
    flags.
*/


/*! Constructs a Copy object parsing uids if \a uid is true, and msns
    if \a uid is false.
*/

Copy::Copy( bool uid )
    : Command(), d( new CopyData )
{
    d->uid = uid;
}


/*! Tells the Copy handler to expunge the messages after copying, in
    effect turning Copy into Move.

*/

void Copy::setMove()
{
    d->move = true;
}


void Copy::parse()
{
    space();
    d->set = set( !d->uid );
    shrink( &d->set );
    space();
    d->mailbox = mailbox();
    end();

    if ( !ok() )
        return;

    requireRight( d->mailbox, Permissions::Insert );
    requireRight( d->mailbox, Permissions::Write );
    if ( d->move ) {
        requireRight( session()->mailbox(), Permissions::Expunge );
        requireRight( session()->mailbox(), Permissions::DeleteMessages );
    }

    log( "Will copy " + fn( d->set.count() ) +
         " messages to " + d->mailbox->name().ascii() );
}


void Copy::execute()
{
    if ( state() != Executing )
        return;

    if ( d->set.isEmpty() ) {
        finish();
        return;
    }

    if ( !permitted() )
        return;

    if ( !d->transaction ) {
        d->transaction = new Transaction( this );

        d->findUid = new Query( "select id,uidnext,nextmodseq from mailboxes "
                                "where id=$1 or id=$2 order by id for update",
                                this );
        d->findUid->bind( 1, d->mailbox->id() );
        if ( d->move )
            d->findUid->bind( 2, session()->mailbox()->id() );
        else
            d->findUid->bind( 2, d->mailbox->id() );
        d->transaction->enqueue( d->findUid );
        d->transaction->execute();
    }

    while ( d->findUid->hasResults() ) {
        Row * r = d->findUid->nextRow();
        if ( (uint)r->getInt( "id" ) == d->mailbox->id() ) {
            d->toUid = r->getInt( "uidnext" );
            d->toMs = r->getBigint( "nextmodseq" );
        }
        else {
            d->fromMs = r->getBigint( "nextmodseq" );
        }
    }

    if ( !d->findUid->done() )
        return;

    if ( !d->report ) {
        if ( !d->toMs )
            error( No, "Could not allocate UID and modseq in target mailbox" );

        if ( !ok() ) {
            d->transaction->rollback();
            return;
        }

        Query * q;

        q = new Query( "create temporary table t ("
                       "mailbox integer,"
                       "uid integer,"
                       "message integer,"
                       "nuid integer,"
                       "seen boolean"
                       ")", 0 );
        d->transaction->enqueue( q );

        q = new Query( "create temporary sequence s start " + fn( d->toUid ),
                       0 );
        d->transaction->enqueue( q );

        q = new Query( "insert into t "
                       "(mailbox, uid, message, nuid, seen) "
                       "select mailbox, uid, message, nextval('s'), seen "
                       "from mailbox_messages "
                       "where mailbox=$1 and uid=any($2) order by uid", 0 );
        q->bind( 1, session()->mailbox()->id() );
        q->bind( 2, d->set );
        d->transaction->enqueue( q );

        q = new Query( "update mailboxes "
                       "set uidnext=nextval('s'), nextmodseq=$1 "
                       "where id=$2",
                       this );
        q->bind( 1, d->toMs+1 );
        q->bind( 2, d->mailbox->id() );
        d->transaction->enqueue( q );

        d->transaction->enqueue( new Query( "drop sequence s", 0 ) );

        q = new Query( "insert into mailbox_messages "
                       "(mailbox, uid, message, modseq, seen, deleted) "
                       "select $1, t.nuid, message, $2, t.seen, false "
                       "from t", 0 );
        q->bind( 1, d->mailbox->id() );
        q->bind( 2, d->toMs );
        d->transaction->enqueue( q );

        q = new Query( "insert into flags "
                       "(mailbox, uid, flag) "
                       "select $1, t.nuid, f.flag "
                       "from flags f join t using (mailbox, uid)", 0 );
        q->bind( 1, d->mailbox->id() );
        d->transaction->enqueue( q );

        q = new Query( "insert into annotations "
                       "(mailbox, uid, owner, name, value) "
                       "select $1, t.nuid, a.owner, a.name, a.value "
                       "from annotations a join t using (mailbox, uid) "
                       "where a.owner is null or a.owner=$2", 0 );
        q->bind( 1, d->mailbox->id() );
        q->bind( 2, imap()->user()->id() );
        d->transaction->enqueue( q );

        d->report = new Query( "select uid, nuid from t", 0 );
        d->transaction->enqueue( d->report );

        if ( d->move ) {
            q = new Query(
                "insert into deleted_messages "
                "(mailbox,uid,message,modseq,deleted_by,reason) "
                "select $1, t.uid, t.message, $2, $3"
                " 'moved to mailbox '||$4||' uid '||t.nuid "
                "from t", 0 );
            q->bind( 1, session()->mailbox()->id() );
            q->bind( 2, d->fromMs );
            q->bind( 3, imap()->user()->id() );
            q->bind( 4, d->mailbox->name() );
            d->transaction->enqueue( q );
            q = new Query( "update mailboxes "
                           "set nextmodseq=$1 "
                           "where id=$2",
                           0 );
            q->bind( 1, d->fromMs+1 );
            q->bind( 2, session()->mailbox()->id() );
            d->transaction->enqueue( q );
        }

        d->transaction->enqueue( new Query( "drop table t", 0 ) );

        Mailbox::refreshMailboxes( d->transaction );

        d->transaction->commit();
    }

    if ( !d->transaction->done() )
        return;

    if ( d->transaction->failed() ) {
        error( No, "Database failure: " + d->transaction->error() );
        return;
    }

    if ( imap() && imap()->session() &&
         imap()->session()->mailbox() == d->mailbox &&
         !imap()->session()->initialised() )
        return;

    IntegerSet from;
    IntegerSet to;

    while ( d->report->hasResults() ) {
        Row * r = d->report->nextRow();
        from.add( r->getInt( "uid" ) );
        to.add( r->getInt( "nuid" ) );
    }

    if ( !from.isEmpty() )
        setRespTextCode( "COPYUID " +
                         fn( d->mailbox->uidvalidity() ) + " " +
                         from.set() + " " + to.set() );
    finish();
}
