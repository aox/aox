// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "expunge.h"

#include "flag.h"
#include "imap.h"
#include "user.h"
#include "query.h"
#include "scope.h"
#include "mailbox.h"
#include "imapsession.h"
#include "permissions.h"
#include "transaction.h"
#include "messageset.h"


class ExpungeData
    : public Garbage
{
public:
    ExpungeData()
        : uid( false ), s( 0 ),
          findUids( 0 ), findModseq( 0 ), expunge( 0 ), t( 0 )
    {}

    bool uid;
    Session * s;
    Query * findUids;
    Query * findModseq;
    Query * expunge;
    Transaction * t;
    MessageSet uids;
};


/*! \class Expunge expunge.h
    This command is responsible for removing "\Deleted" messages.

    It implements EXPUNGE, as specified in RFC 3501 section 6.4.3 and
    UID EXPUNGE, as specified in RFC 2359 section 4.1, and helps
    Close.

    RFC 2180 discusses expunging in situations where multiple users
    may access the mailbox. Our present approach is to delete the
    message early, so that when we tell the expunging client that a
    message is gone, it really is. Seems advisable from a
    confidentiality point of view.

    The UID of an expunged message may still exist in different
    sessions, although the message itself is no longer accessible.
*/

/*! Creates a new EXPUNGE handler if \a u is false, or a UID EXPUNGE
    handler if it is true.
*/

Expunge::Expunge( bool u )
    : d( new ExpungeData )
{
    d->uid = u;
}


void Expunge::parse()
{
    if ( d->uid ) {
        space();
        d->uids = set( false );
        shrink( &d->uids );
    }
    end();
}


/*! Remarkable only in that it cooperates with the reimplementation in
    Close: the ImapSession is copied in on the first call, so that
    Close can nil it out, and if there isn't a session when execute()
    finishes its work, no expunge responses are sent.
*/


void Expunge::execute()
{
    if ( !d->s ) {
        d->s = imap()->session();
        if ( !d->s || !d->s->mailbox() ) {
            error( No, "No mailbox to expunge" );
            return;
        }
        requireRight( d->s->mailbox(), Permissions::Expunge );
    }

    if ( !permitted() || !ok() )
        return;

    if ( !d->t ) {
        Flag * f = Flag::find( "\\deleted" );
        if ( !f ) {
            error( No, "Internal error - no \\Deleted flag" );
            return;
        }

        d->t = new Transaction( this );
        d->findModseq = new Query( "select nextmodseq from mailboxes "
                                   "where id=$1 for update", this );
        d->findModseq->bind( 1, d->s->mailbox()->id() );
        d->t->enqueue( d->findModseq );

        String query( "select uid from flags left join deleted_messages dm "
                      "using (mailbox,uid) where mailbox=$1 and flag=$2 and "
                      "dm.uid is null" );
        if ( d->uid )
            query.append( " and (" + d->uids.where() + ")" );

        d->findUids = new Query( query, this );
        d->findUids->bind( 1, d->s->mailbox()->id() );
        d->findUids->bind( 2, f->id() );
        d->t->enqueue( d->findUids );
        d->t->execute();
        d->uids.clear();
    }

    Row * r;
    while ( ( r = d->findUids->nextRow() ) != 0 ) {
        uint n = r->getInt( "uid" );
        d->uids.add( n );
    }
    if ( !d->findUids->done() )
        return;

    if ( d->uids.isEmpty() ) {
        d->t->rollback();
        finish();
        return;
    }

    if ( !d->expunge ) {
        r = d->findModseq->nextRow();
        int64 modseq = r->getBigint( "nextmodseq" ); // XXX 0

        String w( d->uids.where() );
        log( "Expunge " + fn( d->uids.count() ) + " messages" );
        Query * q
            = new Query( "update modsequences "
                         "set modseq=$2 "
                         "where mailbox=$1 and (" + w + ")", 0 );
        q->bind( 1, d->s->mailbox()->id() );
        q->bind( 1, modseq );
        d->t->enqueue( q );

        d->expunge = new Query( "insert into deleted_messages "
                          "(mailbox, uid, deleted_by, reason) "
                          "select mailbox, uid, $2, $3 "
                          "from messages where mailbox=$1 and (" + w + ")",
                          this );
        d->expunge->bind( 1, d->s->mailbox()->id() );
        d->expunge->bind( 2, imap()->user()->id() );
        d->expunge->bind( 3, "IMAP expunge " + Scope::current()->log()->id() );
        d->t->enqueue( d->expunge );

        q = new Query( "update mailboxes set nextmodseq=$1 "
                       "where id=$2", 0 );
        q->bind( 1, modseq + 1 );
        q->bind( 2, d->s->mailbox()->id() );
        d->t->enqueue( q );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( No, "Database error. Messages not expunged." );

    d->s->expunge( d->uids );
    finish();
}
