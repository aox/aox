// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "delete.h"

#include "date.h"
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
    DeleteData(): m( 0 ), messages( 0 ), first( true ) {}

    Mailbox * m;
    Query * messages;
    bool first;
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
    if ( ok() )
        log( "Delete mailbox: " + d->m->name().ascii() );
}


void Delete::execute()
{
    if ( state() != Executing || !ok() )
        return;

    if ( d->first ) {
        d->first = false;

        // We should really require DeleteMessages and Expunge only if
        // we know the mailbox isn't empty; but we'll know that inside
        // the transaction, and permitted() won't let us clean that up
        // if we don't have permission. So it'll have to wait until we
        // query permissions ourselves.

        requireRight( d->m, Permissions::DeleteMailbox );
        requireRight( d->m, Permissions::DeleteMessages );
        requireRight( d->m, Permissions::Expunge );
    }

    if ( !permitted() )
        return;

    if ( !transaction() ) {
        setTransaction( new Transaction( this ) );
        Query * lock = new Query( "select * from mailboxes "
                                  "where id=$1 for update", 0 );
        lock->bind( 1, d->m->id() );
        transaction()->enqueue( lock );

        d->messages = new Query( "select count(mm.uid)::bigint as messages "
                                 "from mailbox_messages mm "
                                 "join messages m on (mm.message=m.id) "
                                 "join mailboxes mb on (mm.mailbox=mb.id) "
                                 "where mm.mailbox=$1 and not mm.seen and "
                                 "(mm.uid>=mb.first_recent or m.idate>$2)",
                                 this );
        d->messages->bind( 1, d->m->id() );
        Date now;
        now.setCurrentTime();
        d->messages->bind( 2, now.unixTime() - 20 );
        transaction()->enqueue( d->messages );
        transaction()->execute();
    }

    if ( d->messages ) {
        if ( !d->messages->done() )
            return;

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

        if ( ok() && d->m->remove( transaction() ) == 0 )
            error( No, "Cannot delete mailbox " + d->m->name().ascii() );

        Mailbox::refreshMailboxes( transaction() );
        transaction()->commit();
    }

    if ( !transaction()->done() )
        return;

    if ( transaction()->failed() ) {
        error( No, "Database error: " + transaction()->error() );
        return;
    }

    finish();
}
