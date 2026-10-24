// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "expunge.h"

#include "flag.h"
#include "imap.h"
#include "mover.h"
#include "user.h"
#include "query.h"
#include "scope.h"
#include "mailbox.h"
#include "selector.h"
#include "integerset.h"
#include "imapsession.h"
#include "permissions.h"
#include "transaction.h"


class ExpungeData
    : public Garbage
{
public:
    ExpungeData()
        : uid( false ), commit( false ), modseq( 0 ), s( 0 ),
          findUids( 0 ), findModseq( 0 ), expunge( 0 ), r( 0 ),
          mover( 0 )
    {}

    bool uid;
    bool commit;
    int64 modseq;
    Session * s;
    Query * findUids;
    Query * findModseq;
    Query * expunge;
    IntegerSet requested;
    IntegerSet marked;
    IntegerSet expungeable;
    RetentionSelector * r;
    Mover * mover;
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

    if ( !d->r ) {
        d->r = new RetentionSelector( d->s->mailbox(), this );
        d->r->execute();
    }

    if ( !transaction() ) {
        setTransaction( new Transaction( this ) );

        Query * lock = new Query( "select id from mailboxes "
                                  "where id=$1 for update", this );
        lock->bind( 1, d->s->mailbox()->id() );
        transaction()->enqueue( lock );

        d->findUids = new Query( "", this );
        d->findUids->bind( 1, d->s->mailbox()->id() );
        EString query( "select uid from mailbox_messages "
                       "where mailbox=$1 and deleted" );
        if ( d->uid ) {
            query.append( " and uid=any($2)" );
            d->findUids->bind( 2, d->requested );
        }
        query.append( " order by uid for update" );
        d->findUids->setString( query );
        transaction()->enqueue( d->findUids );

        transaction()->execute();
    }

    while ( d->findUids->hasResults() ) {
        Row * r = d->findUids->nextRow();
        d->marked.add( r->getInt( "uid" ) );
    }

    if ( !d->findUids->done() )
        return;

    if ( !d->r->done() )
        return;

    if ( d->marked.isEmpty() ) {
        transaction()->commit();
        finish();
        return;
    }

    if ( !d->expunge ) {
        log( "Expunge " + fn( d->marked.count() ) + " messages: " +
             d->marked.set() );

        Selector * s = new Selector;
        s->add( new Selector( d->marked ) );
        if ( d->r->retains() ) {
            Selector * n = new Selector( Selector::Not );
            s->add( n );
            n->add( d->r->retains() );
        }
        s->simplify();

        EStringList wanted;
        wanted.append( "uid" );

        // Mover does the deleting, or the moving to trash, so we only
        // have to say which messages the retention policy permits.
        d->expunge = s->query( imap()->user(), d->s->mailbox(),
                               d->s, this, false, &wanted,
                               false );
        transaction()->enqueue( d->expunge );
        transaction()->execute();
    }

    while ( d->expunge->hasResults() )
        d->expungeable.add( d->expunge->nextRow()->getInt( "uid" ) );

    if ( !d->expunge->done() )
        return;

    if ( !d->mover && !d->expungeable.isEmpty() )
        d->mover = new Mover( transaction(), imap()->user(),
                              d->s->mailbox(), 0,
                              d->expungeable, 0, true );

    if ( d->mover ) {
        if ( !d->mover->done() )
            return;
        d->modseq = d->mover->modseq();
    }

    IntegerSet retained( d->marked );
    retained.remove( d->expungeable );

    if ( !retained.isEmpty() && !d->modseq ) {
        if ( !d->findModseq ) {
            d->findModseq = new Query( "select nextval('nextmodseq') "
                                       "as nextmodseq", this );
            transaction()->enqueue( d->findModseq );
            transaction()->execute();
        }
        if ( !d->findModseq->done() )
            return;
        Row * r = d->findModseq->nextRow();
        if ( r )
            d->modseq = r->getBigint( "nextmodseq" );
    }

    if ( !d->commit ) {
        d->commit = true;
        if ( !retained.isEmpty() ) {
            log( "User requested expunging " + fn( d->marked.count() ) +
                 " messages, of which " + fn ( retained.count() ) +
                 " must be retained" );
            // there was something we were asked to expunge, but which
            // must be retained due to a configured policy. clear the
            // deleted flag on those messages, so the retention policy
            // is clearly visible.
            Query * q = new Query( "update mailbox_messages "
                                   "set modseq=$1, deleted=false "
                                   "where mailbox=$2 and uid=any($3)",
                                   0 );
            q->bind( 1, d->modseq );
            q->bind( 2, d->s->mailbox()->id() );
            q->bind( 3, retained );
            transaction()->enqueue( q );

            q = new Query( "update mailboxes set nextmodseq=$1 "
                           "where id=$2", 0 );
            q->bind( 1, d->modseq + 1 );
            q->bind( 2, d->s->mailbox()->id() );
            transaction()->enqueue( q );
        }

        Mailbox::refreshMailboxes( transaction() );
        transaction()->commit();
    }

    if ( !transaction()->done() )
        return;

    if ( transaction()->failed() ||
         transaction()->state() == Transaction::RolledBack )
        error( No, "Database error. Messages not expunged." );
    finish();
}
