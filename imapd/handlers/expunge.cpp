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
        : stage( 0 ), t( 0 ), q1( 0 ), q2( 0 )
    {}

    int stage;
    Transaction *t;
    Query *q1, *q2;
    MessageSet uids;
};


/*! \class Expunge expunge.h
    This command is responsible for removing "\Deleted" messages.

    It implements EXPUNGE, as specified in RFC 3501 section 6.4.3, and
    helps Close.
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
    if ( !d->t ) {
        d->t = new Transaction( this );
        d->q1 =
            new Query( "select uid from messages where deleted='t' "
                       "and mailbox=$1 for update", this );
        d->q1->bind( 1, imap()->session()->mailbox()->id() );
        d->t->enqueue( d->q1 );

        // Find all referenced bodyparts.
        d->q2 =
            new Query( "select distinct(bodypart) "
                       "from part_numbers p, messages m "
                       "where m.mailbox=p.mailbox and m.uid=p.uid and "
                       "m.deleted='t' and p.mailbox=$1 and "
                       "p.bodypart is not null", this );
        d->q2->bind( 1, imap()->session()->mailbox()->id() );
        d->t->enqueue( d->q2 );
        d->t->execute();
        d->stage = 1;
    }

    if ( d->stage == 1 && d->q1->done() ) {
        Row *r;
        String uids;
        while ( ( r = d->q1->nextRow() ) != 0 ) {
            uint n = r->getInt( "uid" );
            uids.append( "," + fn( n ) );
            d->uids.add( n );
        }
        uids = uids.mid( 1 );

        if ( !uids.isEmpty() ) {
            Query *q;
            q = new Query( "delete from messages where mailbox=$1 and "
                           "uid in (" + uids + ")", this );
            q->bind( 1, imap()->session()->mailbox()->id() );
            d->t->enqueue( q );
            d->t->execute();
        }
        d->stage = 2;
    }

    if ( d->stage == 2 && d->q2->done() ) {
        Row *r;
        String parts;
        while ( ( r = d->q2->nextRow() ) != 0 ) {
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
        d->stage = 3;
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
