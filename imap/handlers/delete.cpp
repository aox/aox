// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "delete.h"

#include "imap.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "session.h"
#include "transaction.h"


class DeleteData
    : public Garbage
{
public:
    DeleteData(): m( 0 ), messages( 0 ), t( 0 ) {}

    Mailbox * m;
    Query * messages;
    Transaction * t;
};


/*! \class Delete delete.h
    Deletes an existing mailbox (RFC 3501 section 6.3.4)

    Mailboxes cannot be deleted until they're empty of messages and 

    (Really deletes? What happens to the mail there?)

    RFC 2180 section 3 is tricky. For the moment we disallow DELETE of
    an active mailbox. That's not practical to do on a cluster, so
    we'll need to think of a better policy.
*/

Delete::Delete()
    : d( new DeleteData )
{
}


void Delete::parse()
{
    space();
    d->m = mailbox();
    end();
    if ( d->m == imap()->user()->inbox() )
            error( No, "Cannot delete INBOX" );
    if ( ok() )
        log( "Delete mailbox: " + d->m->name().ascii() );
}


void Delete::execute()
{
    if ( state() != Executing )
        return;

    if ( d->m->sessions() ) {
        error( No, "Mailbox is in use" );
        setRespTextCode( "INUSE" );
    }
    else if ( d->m->synthetic() ) {
        error( No,
               d->m->name().ascii() + " does not really exist anyway" );
        setRespTextCode( "NONEXISTENT" );
    }

    if ( !ok() )
        return;

    if ( !d->t ) {
        d->t = new Transaction( this );
        Query * lock = new Query( "select * from mailboxes "
                                  "where id=$1 for update", 0 );
        lock->bind( 1, d->m->id() );
        d->t->enqueue( lock );

        d->messages = new Query(
            "select "
            "(select count(*)::bigint from mailbox_messages where mailbox=$1) "
            "+"
            "(select count(*)::bigint from deleted_messages where mailbox=$1) "
            "as messages",
            this );
        d->messages->bind( 1, d->m->id() );
        d->t->enqueue( d->messages );
        d->t->execute();

        requireRight( d->m, Permissions::DeleteMailbox );
        requireRight( d->m, Permissions::DeleteMessages );
        requireRight( d->m, Permissions::Expunge );
    }

    if ( !permitted() )
        return;

    if ( d->messages && !d->messages->done() )
        return;

    if ( d->messages ) {
        int64 messages = 0;

        Row * r = d->messages->nextRow();
        if ( d->messages->failed() || !r )
            error( No, "Could not determine if any messages exist" );
        else
            messages = r->getBigint( "messages" );

        if ( messages )
            error( No, "Cannot delete mailbox: " + fn( messages ) +
                   " messages exist" );
        d->messages = 0;

        if ( !ok() )
            return;

        if ( d->m->remove( d->t ) == 0 ) {
            error( No, "Cannot delete mailbox " + d->m->name().ascii() );
            return;
        }
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        error( No, "Database error: " + d->t->error() );
        return;
    }

    finish();
}
