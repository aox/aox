// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "obliterate.h"

#include "imap.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "transaction.h"


/*! \class XObliterate obliterate.h

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


void XObliterate::parse()
{
    space();
    n = astring();
    end();
}


void XObliterate::execute()
{
    if ( n != "whip" ) {
        error( No,
               "Wenn Du zur Fliegenden Archiv gehst, "
               "vergiss nicht die Peitsche" );
        return;
    }

    if ( !t ) {
        t = new Transaction( this );

        User * user = imap()->user();
        Mailbox * inbox = user->inbox();

        Query * q;

        q = new Query( "update mailboxes set owner=$1 where id=$2",
                       this );
        q->bind( 1, user->id() );
        q->bind( 2, inbox->id() );
        t->enqueue( q );

        q = new Query( "delete from aliases "
                       "where mailbox=$1 and "
                       "id not in (select alias from users)",
                       this );
        q->bind( 1, user->inbox()->id() );
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

        q = new Query( "delete from subscriptions where owner=$1",
                       this );
        q->bind( 1, user->id() );
        t->enqueue( q );

        q = new Query( "delete from annotations where owner=$1", this );
        q->bind( 1, user->id() );
        t->enqueue( q );

        q = new Query( "delete from views where source in "
                       "(select id from mailboxes where owner=$1)",
                       this );
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
                       "deleted='t',owner=null,"
                       "uidvalidity=1,uidnext=1,first_recent=1 "
                       "where (owner=$1 or name like $3||'/%') "
                       "and id<>$2", this );
        q->bind( 1, user->id() );
        q->bind( 2, inbox->id() );
        q->bind( 3, user->home()->name() );
        t->enqueue( q );

        q = new Query( "update mailboxes "
                       "set uidnext=1,first_recent=1,uidvalidity=1 "
                       "where id=$1", this );
        q->bind( 1, inbox->id() );
        t->enqueue( q );

        inbox->setUidnext( 1 );
        inbox->clear();

        t->enqueue( inbox->refresh() );
    }

    if ( a ) {
        Row * r;
        while ( (r=a->nextRow()) != 0 ) {
            Mailbox * m = Mailbox::find( r->getInt( "id" ) );
            if ( m )
                t->enqueue( m->refresh() );
        }
        if ( a->done() )
            t->commit();
    }

    if ( t->done() )
        finish();
}
