// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "expunge.h"

#include "imap.h"
#include "query.h"
#include "mailbox.h"
#include "transaction.h"
#include "imapsession.h"
#include "messageset.h"


class ExpungeData {
public:
    ExpungeData()
        : stage( 0 ), q( 0 ), t( 0 )
    {}

    int stage;
    Query *q;
    Transaction *t;
    String uidlist;
    MessageSet uids;
};


/*! \class Expunge expunge.h
    This command is responsible for removing "\Deleted" messages.

    It implements EXPUNGE, as specified in RFC 3501 section 6.4.3, and
    helps Close.

    RFC 2180 discusses expunging in situations where multiple users
    may access the mailbox. Our present approach is to delete the
    message early, so that when we tell the expunging client that a
    message is gone, it really is. Seems advisable from a
    confidentiality point of view.

    The UID of an expunged message may still exist in different
    sessions, although the message itself is no longer accessible.
*/

/*! Creates a new Expunge handler.
*/

Expunge::Expunge()
    : d( new ExpungeData )
{
}


/*! This function expunges the current mailbox, emitting EXPUNGE
    responses if \a chat is true and being silent if \a chat is false.
*/

bool Expunge::expunge( bool chat )
{
    if ( d->stage == 0 ) {
        d->t = new Transaction( this );
        d->q =
            new Query( "select uid from flags where mailbox=$1 and flag="
                       "(select id from flag_names where name='\\\\Deleted')",
                       this );
        d->q->bind( 1, imap()->session()->mailbox()->id() );
        d->t->enqueue( d->q );
        d->t->execute();
        d->stage = 1;
    }

    if ( d->stage == 1 && d->q->done() ) {
        Row *r;
        while ( ( r = d->q->nextRow() ) != 0 ) {
            uint n = r->getInt( "uid" );
            d->uidlist.append( "," + fn( n ) );
            d->uids.add( n );
        }
        d->uidlist = d->uidlist.mid( 1 );

        d->stage = 2;
        if ( d->uids.isEmpty() ) {
            d->stage = 4;
            d->t->commit();
        }
    }

    if ( d->stage == 2 ) {
        Query *q =
            new Query( "delete from messages where mailbox=$1 and "
                       "uid in (" + d->uidlist + ")", this );
        q->bind( 1, imap()->session()->mailbox()->id() );
        d->t->enqueue( q );

        d->q =
            new Query( "select distinct(bodypart) from part_numbers "
                       "where mailbox=$1 and bodypart is not null and "
                       "uid in (" + d->uidlist + ")", this );
        d->q->bind( 1, imap()->session()->mailbox()->id() );
        d->t->enqueue( d->q );
        d->t->execute();
        d->stage = 3;
    }

    if ( d->stage == 3 && d->q->done() ) {
        Row *r;
        String parts;
        while ( ( r = d->q->nextRow() ) != 0 ) {
            uint n = r->getInt( "bodypart" );
            parts.append( "," + fn( n ) );
        }
        parts = parts.mid( 1 );

        // Delete unreferenced bodyparts.
        if ( !parts.isEmpty() ) {
            Query *q;
            q = new Query( "delete from bodyparts where id in (" + parts + ") "
                           "and id not in "
                           "(select bodypart from part_numbers where"
                           " bodypart in (" + parts + "))", this );
            d->t->enqueue( q );
        }
        d->t->commit();
        d->stage = 4;
    }

    if ( d->t->done() ) {
        if ( d->t->failed() ) {
            error( No, "Database error. Messages not expunged." );
        }
        else if ( chat ) {
            uint i = 1;
            while ( i <= d->uids.count() ) {
                uint uid = d->uids.value( i );
                uint msn = imap()->session()->msn( uid );
                imap()->session()->remove( uid );
                respond( fn( msn ) + " EXPUNGE" );
                i++;
            }
        }
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
