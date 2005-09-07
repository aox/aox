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

        Query * q = new Query( "delete from messages where mailbox in "
                               "(select id from mailboxes where owner=$1)",
                               this );
        q->bind( 1, user->id() );
        t->enqueue( q );
 
        // and just in case the inbox doesn't have the right owner,
        // delete it too
        q = new Query( "delete from messages where mailbox=$1",
                       this );
        q->bind( 1, inbox->id() );
        t->enqueue( q );
        
        q = new Query( "delete from subscriptions where mailbox in "
                       "(select id from mailboxes where owner=$1)",
                       this );
        q->bind( 1, user->id() );
        t->enqueue( q );

        q = new Query( "delete from permissions where mailbox in "
                       "(select id from mailboxes where owner=$1)",
                       this );
        q->bind( 1, user->id() );
        t->enqueue( q );

        q = new Query( "update mailboxes set uidnext=1,first_recent=1"
                       " where id=$1",
                       this );
        q->bind( 1, inbox->id() );
        t->enqueue( q );
        
        q = new Query( "delete from mailboxes where owner=$1 and id!=$2",
                       this );
        q->bind( 1, user->id() );
        q->bind( 2, inbox->id() );
        t->enqueue( q );

#if 0
        // properly speaking we should kill the unused flags to... but
        // leave the system flags. the resulting sql looks too ugly. I
        // won't do it.
        q = new Query( "delete from flag_names where not id in "
                       "(select distinct flag from flags)",
                       this );
        t->enqueue( q );
#endif

        t->execute();
        t->commit();
        
        inbox->setUidnext( 1 );
        inbox->clear();
    }

    if ( t->done() )
        finish();
}
