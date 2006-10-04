// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "copy.h"

#include "imapsession.h"
#include "transaction.h"
#include "messageset.h"
#include "occlient.h"
#include "mailbox.h"
#include "query.h"
#include "user.h"


class CopyData
    : public Garbage
{
public:
    CopyData() :
        uid( false ), firstUid( 0 ), modseq( 0 ),
        mailbox( 0 ), transaction( 0 ),
        findUid( 0 ), findModseq( 0 ),
        totalQueries( 0 ), completedQueries( 0 )
    {}
    bool uid;
    MessageSet set;
    String target;
    uint firstUid;
    uint modseq;
    Mailbox * mailbox;
    Transaction * transaction;
    Query * findUid;
    Query * findModseq;
    uint totalQueries;
    uint completedQueries;
};


/*! \class Copy copy.h

    The Copy class implements the IMAP COPY command (RFC 3501 section
    6.4.7), as extended by RFC 2359.

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


void Copy::parse()
{
    space();
    d->set = set( !d->uid );
    shrink( &d->set );
    space();
    d->target = astring();
    end();
    if ( ok() )
        log( "Will copy " + fn( d->set.count() ) +
             " messages to " + d->target );
}


void Copy::execute()
{
    if ( d->set.isEmpty() ) {
        finish();
        return;
    }

    if ( !d->mailbox ) {
        d->mailbox = mailbox( d->target );
        if ( !d->mailbox ) {
            error( No, "Cannot find any mailbox named " + d->target );
            return;
        }
        requireRight( d->mailbox, Permissions::Insert );
        requireRight( d->mailbox, Permissions::Write );
    }

    if ( !permitted() )
        return;

    if ( !d->findUid ) {
        d->transaction = new Transaction( this );
        d->findUid = new Query( "select uidnext from mailboxes "
                                "where id=$1 for update",
                                this );
        d->findUid->bind( 1, d->mailbox->id() );
        d->transaction->enqueue( d->findUid );
        d->findModseq 
            = new Query( "select nextval('nextmodsequence')::int as ms",
                         this );
        d->transaction->enqueue( d->findModseq );
        d->transaction->execute();
    }
    if ( !d->findUid->done() || !d->findModseq->done() )
        return;

    if ( !d->firstUid ) {
        Row * r = d->findUid->nextRow();
        if ( r )
            d->firstUid = r->getInt( "uidnext" );
        else
            error( No, "Could not allocate UID in target mailbox" );

        r = d->findModseq->nextRow();
        if ( r )
            d->modseq = r->getInt( "ms" );
        else
            error( No, "Could not obtain modseq" );

        if ( !ok() ) {
            d->transaction->rollback();
            return;
        }

        Mailbox * current = imap()->session()->mailbox();
        Query * q;

        uint cmailbox = current->id();
        uint tmailbox = d->mailbox->id();
        uint tuid = d->firstUid;
        uint i = 1;
        while ( i <= d->set.count() ) {
            uint cuid = d->set.value( i );
            uint j = i + 1;
            while ( j-i == d->set.value( j ) - cuid && j < i+1024 )
                j++;

            q = new Query( "insert into messages "
                           "(mailbox, uid, idate, rfc822size) "
                           "select $1, uid+$2, idate, rfc822size from messages "
                           "where mailbox=$3 and uid>=$4 and uid<$5",
                           this );
            q->bind( 1, tmailbox );
            q->bind( 2, tuid-cuid );
            q->bind( 3, cmailbox );
            q->bind( 4, cuid );
            q->bind( 5, cuid + j - i );
            d->transaction->enqueue( q );

            q = new Query( "insert into part_numbers "
                           "(mailbox, uid, part, bodypart, bytes, lines) "
                           "select $1, uid+$2, part, bodypart, bytes, lines "
                           "from part_numbers "
                           "where mailbox=$3 and uid>=$4 and uid<$5",
                           this );
            q->bind( 1, tmailbox );
            q->bind( 2, tuid-cuid );
            q->bind( 3, cmailbox );
            q->bind( 4, cuid );
            q->bind( 5, cuid + j - i );
            d->transaction->enqueue( q );

            q = new Query( "insert into header_fields "
                           "(mailbox, uid, part, position, field, value) "
                           "select $1, uid+$2, part, position, field, value "
                           "from header_fields "
                           "where mailbox=$3 and uid>=$4 and uid<$5",
                           this );
            q->bind( 1, tmailbox );
            q->bind( 2, tuid-cuid );
            q->bind( 3, cmailbox );
            q->bind( 4, cuid );
            q->bind( 5, cuid + j - i );
            d->transaction->enqueue( q );

            q = new Query( "insert into address_fields "
                           "(mailbox, uid, part, position, field, address) "
                           "select $1, uid+$2, part, position, field, address "
                           "from address_fields "
                           "where mailbox=$3 and uid>=$4 and uid<$5",
                           this );
            q->bind( 1, tmailbox );
            q->bind( 2, tuid-cuid );
            q->bind( 3, cmailbox );
            q->bind( 4, cuid );
            q->bind( 5, cuid + j - i );
            d->transaction->enqueue( q );

            q = new Query( "insert into flags "
                           "(mailbox, uid, flag) "
                           "select $1, uid+$2, flag "
                           "from flags "
                           "where mailbox=$3 and uid>=$4 and uid<$5",
                           this );
            q->bind( 1, tmailbox );
            q->bind( 2, tuid-cuid );
            q->bind( 3, cmailbox );
            q->bind( 4, cuid );
            q->bind( 5, cuid + j - i );
            d->transaction->enqueue( q );

            q = new Query( "insert into annotations "
                           "(mailbox, uid, owner, name, value) "
                           "select $1, uid+$2, $5, name, value "
                           "from annotations "
                           "where mailbox=$3 and uid>=$4 and uid<$5 and "
                           "(owner is null or owner=$6)",
                           this );
            q->bind( 1, tmailbox );
            q->bind( 2, tuid-cuid );
            q->bind( 3, cmailbox );
            q->bind( 4, cuid );
            q->bind( 5, cuid + j - i );
            q->bind( 6, imap()->user()->id() );
            d->transaction->enqueue( q );

            tuid = tuid + j - i;
            i = j;
        }

        // could this be done faster?
        q = new Query( "insert into modsequences (mailbox, uid, modseq) "
                       "select $1, uid, $2 from messages "
                       "where mailbox=$1 and uid>=$3 and uid<$4",
                       this );
        q->bind( 1, tmailbox );
        q->bind( 2, d->modseq );
        q->bind( 3, d->firstUid );
        q->bind( 4, tuid );
        d->transaction->enqueue( q );

        q = new Query( "update mailboxes set uidnext=$1 where id=$2",
                       this );
        q->bind( 1, tuid );
        q->bind( 2, tmailbox );
        d->transaction->enqueue( q );

        d->totalQueries = d->transaction->queries()->count();
        d->completedQueries = 0;
        d->transaction->commit();
    }

    if ( d->totalQueries > 10 ) {
        uint completed = 0;
        List<Query>::Iterator i( d->transaction->queries() );
        while ( i ) {
            if ( i->state() == Query::Completed )
                completed++;
            ++i;
        }
        while ( d->completedQueries < completed ) {
            imap()->enqueue( "* OK [PROGRESS " + 
                             tag() + " " +
                             fn( d->completedQueries ) + " " + fn( d->totalQueries ) +
                             "] working\r\n" );
            d->completedQueries++;
        }
    }

    if ( !d->transaction->done() )
        return;

    if ( imap()->session() && d->mailbox == imap()->session()->mailbox() ) {
        imap()->session()->refresh( this );
        if ( !imap()->session()->initialised() )
            return;
    }

    if ( d->transaction->failed() ) {
        error( No, "Database failure: " + d->transaction->error() );
        return;
    }

    uint next = d->firstUid + d->set.count();
    if ( d->mailbox->uidnext() <= next ) {
        d->mailbox->setUidnext( next );
        OCClient::send( "mailbox " + d->mailbox->name().quoted() + " "
                        "uidnext=" + fn( next ) );
    }


    MessageSet target;
    target.add( d->firstUid, next - 1 );
    setRespTextCode( "COPYUID " +
                     fn( d->mailbox->uidvalidity() ) +
                     " " +
                     d->set.set() +
                     " " +
                     target.set() );
    finish();
}
