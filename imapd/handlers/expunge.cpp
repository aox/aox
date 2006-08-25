// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "expunge.h"

#include "flag.h"
#include "imap.h"
#include "user.h"
#include "query.h"
#include "scope.h"
#include "mailbox.h"
#include "transaction.h"
#include "imapsession.h"
#include "permissions.h"
#include "messageset.h"


class ExpungeData
    : public Garbage
{
public:
    ExpungeData()
        : stage( 0 ), q( 0 ), t( 0 )
    {}

    bool uid;
    int stage;
    Query *q;
    Transaction *t;
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


/*! This function expunges the current mailbox, emitting EXPUNGE
    responses if \a chat is true and being silent if \a chat is false.

    It returns true if the job was done, and false if it needs to be
    called again.
*/

bool Expunge::expunge( bool chat )
{
    if ( d->stage == 0 ) {
        Permissions * p = imap()->session()->permissions();
        if ( !p->allowed( Permissions::Expunge ) ) {
            error( No, "Do not have privileges to expunge" );
            return true;
        }
        Flag * f = Flag::find( "\\deleted" );
        d->t = new Transaction( this );
        if ( d->uid )
            d->q = new Query( "select uid from flags "
                              "where mailbox=$1 and flag=$2"
                              " and (" + d->uids.where() + ")",
                              this );
        else
            d->q = new Query( "select uid from flags "
                              "where mailbox=$1 and flag=$2",
                              this );
        d->q->bind( 1, imap()->session()->mailbox()->id() );
        d->q->bind( 2, f->id() );
        d->t->enqueue( d->q );
        d->t->execute();
        d->stage = 1;
        d->uids.clear();
    }

    if ( d->stage == 1 && d->q->done() ) {
        Row *r;
        while ( ( r = d->q->nextRow() ) != 0 ) {
            uint n = r->getInt( "uid" );
            d->uids.add( n );
        }

        d->stage = 2;
        if ( d->uids.isEmpty() ) {
            d->stage = 4;
            d->t->commit();
        }
    }

    if ( d->stage == 2 ) {
        log( "Expunge " + fn( d->uids.count() ) + " messages" );
        Query * q = new Query( "insert into deleted_messages "
                               "(mailbox, uid, deleted_by, reason) "
                               "select mailbox, uid, $2, $3 "
                               "from messages where mailbox=$1 and "
                               "(" + d->uids.where() + ")",
                               this );
        q->bind( 1, imap()->session()->mailbox()->id() );
        q->bind( 2, imap()->user()->id() );
        q->bind( 3, "IMAP expunge " + Scope::current()->log()->id() );
        d->t->enqueue( q );
        d->t->commit();
        d->stage = 4;
    }

    if ( d->t->done() ) {
        if ( d->t->failed() )
            error( No, "Database error. Messages not expunged." );
        else if ( chat )
            imap()->session()->expunge( d->uids );
        imap()->session()->emitResponses();
        return true;
    }

    return false;
}


void Expunge::execute()
{
    if ( !expunge( true ) )
        return;
    finish();
}
