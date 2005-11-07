// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "reset.h"

#include "imap.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "transaction.h"


/*! \class XOryxReset reset.h

    Resets an account, in the hard way. This command breaks various
    invariants, so it cannot be used on a production mail server. It
    exists strictly for regression testing on Oryx' own test servers.

    Deletes all the messages in the authenticated user's inbox and
    sets UIDNEXT to 1. (Decreasing UIDNEXT breaks both an Oryx
    invariant and an IMAP one.)

    Deletes all mailboxes belonging to the authenticated user except
    the input, and all messages in those mailboxes. (This breaks both
    the Oryx mailbox cache and an IMAP invariant.)

    Deletes all unused flag names. (This breaks the flag name cache.)
*/


void XOryxReset::execute()
{
    if ( !t ) {
        t = new Transaction( this );

        User * user = imap()->user();
        Mailbox * inbox = user->inbox();

        Query * q = new Query( "update mailboxes set owner=$1 where id=$2",
                               this );
        q->bind( 1, user->id() );
        q->bind( 2, inbox->id() );
        t->enqueue( q );

        q = new Query( "delete from messages where mailbox in "
                       "(select id from mailboxes where owner=$1)",
                       this );
        q->bind( 1, user->id() );
        t->enqueue( q );

        q = new Query( "delete from subscriptions where mailbox in "
                       "(select id from mailboxes where owner=$1)",
                       this );
        q->bind( 1, user->id() );
        t->enqueue( q );

        q = new Query( "delete from annotations where owner=$1", this );
        q->bind( 1, user->id() );
        t->enqueue( q );

        q = new Query( "delete from permissions where mailbox in "
                       "(select id from mailboxes where owner=$1)",
                       this );
        q->bind( 1, user->id() );
        t->enqueue( q );

        a = new Query( "select id from mailboxes where owner=$1 "
                       "and id<>$2", this );
        a->bind( 1, user->id() );
        a->bind( 2, inbox->id() );
        t->enqueue( a );

        q = new Query( "update mailboxes set "
                       "deleted='t',owner=null,uidnext=1,first_recent=1 "
                       "where owner=$1 and id<>$2", this );
        q->bind( 1, user->id() );
        q->bind( 2, inbox->id() );
        t->enqueue( q );

        q = new Query( "update mailboxes set uidnext=1,first_recent=1 "
                       "where id=$1", this );
        q->bind( 1, inbox->id() );
        t->enqueue( q );

        t->commit();

        inbox->setUidnext( 1 );
        inbox->clear();
    }

    if ( a ) {
        Row * r;
        while ( (r=a->nextRow()) != 0 ) {
            Mailbox * m = Mailbox::find( r->getInt( "id" ) );
            if ( m ) {
                m->setDeleted( true );
                m->setOwner( 0 );
            }
        }
    }

    if ( t->done() )
        finish();
}
