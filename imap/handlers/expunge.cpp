// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "expunge.h"

#include "flag.h"
#include "imap.h"
#include "user.h"
#include "query.h"
#include "scope.h"
#include "mailbox.h"
#include "messageset.h"
#include "imapsession.h"
#include "permissions.h"
#include "transaction.h"


class ExpungeData
    : public Garbage
{
public:
    ExpungeData()
        : uid( false ), modseq( 0 ), s( 0 ),
          findUids( 0 ), findModseq( 0 ), expunge( 0 ), t( 0 )
    {}

    bool uid;
    int64 modseq;
    Session * s;
    Query * findUids;
    Query * findModseq;
    Query * expunge;
    Transaction * t;
    MessageSet requested;
    MessageSet marked;
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
        d->requested = set( false );
        shrink( &d->requested );
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
    if ( state() != Executing )
        return;
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

    if ( d->uid && d->requested.isEmpty() ) {
        finish();
        return;
    }

    if ( !d->t ) {
        uint fid = Flag::id( "\\deleted" );
        if ( fid == 0 ) {
            error( No, "Internal error - no \\Deleted flag" );
            return;
        }

        d->t = new Transaction( this );

        d->findUids = new Query( "", this );
        d->findUids->bind( 1, d->s->mailbox()->id() );
        d->findUids->bind( 2, fid );
        String query( "select uid from mailbox_messages "
                      "where (mailbox,uid) in "
                      "(select mailbox, uid from flags"
                      " where mailbox=$1 and flag=$2" );
        if ( d->uid ) {
            query.append( " and uid=any($3)" );
            d->findUids->bind( 3, d->requested );
        }
        query.append( ") order by mailbox, uid for update" );
        d->findUids->setString( query );
        d->t->enqueue( d->findUids );

        d->findModseq = new Query( "select nextmodseq from mailboxes "
                                   "where id=$1 for update", this );
        d->findModseq->bind( 1, d->s->mailbox()->id() );
        d->t->enqueue( d->findModseq );

        d->t->execute();
    }

    Row * r;
    while ( ( r = d->findUids->nextRow() ) != 0 ) {
        d->marked.add( r->getInt( "uid" ) );
    }

    if ( d->findModseq->hasResults() ) {
        r = d->findModseq->nextRow();
        d->modseq = r->getBigint( "nextmodseq" );
    }

    if ( !d->findModseq->done() )
        return;

    if ( d->marked.isEmpty() ) {
        d->t->commit();
        finish();
        return;
    }

    if ( !d->expunge ) {
        log( "Expunge " + fn( d->marked.count() ) + " messages: " +
             d->marked.set() );

        d->expunge =
            new Query( "insert into deleted_messages "
                       "(mailbox,uid,message,modseq,deleted_by,reason) "
                       "select mailbox,uid,message,$4,$2,$3 "
                       "from mailbox_messages where mailbox=$1 "
                       "and uid=any($5)",
                       this );
        d->expunge->bind( 1, d->s->mailbox()->id() );
        d->expunge->bind( 2, imap()->user()->id() );
        d->expunge->bind( 3, "IMAP expunge " + Scope::current()->log()->id() );
        d->expunge->bind( 4, d->modseq );
        d->expunge->bind( 5, d->marked );
        d->t->enqueue( d->expunge );

        Query * q = new Query( "update mailboxes set nextmodseq=$1 "
                               "where id=$2", 0 );
        q->bind( 1, d->modseq + 1 );
        q->bind( 2, d->s->mailbox()->id() );
        d->t->enqueue( q );
        Mailbox::refreshMailboxes( d->t );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( No, "Database error. Messages not expunged." );
    finish();
}
