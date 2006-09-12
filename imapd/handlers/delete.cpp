// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "delete.h"

#include "imap.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "session.h"
#include "occlient.h"
#include "permissions.h"
#include "transaction.h"


class DeleteData
    : public Garbage
{
public:
    DeleteData(): m( 0 ), q( 0 ), t( 0 ), p( 0 ) {}

    String n;
    Mailbox * m;
    Query * q;
    Transaction * t;
    Permissions * p;
};


/*! \class Delete delete.h
    Deletes an existing mailbox (RFC 3501 section 6.3.4)

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
    d->n = astring();
    end();
    log( "Delete mailbox: " + d->n );
}


void Delete::execute()
{
    if ( !d->m ) {
        d->m = Mailbox::obtain( mailboxName( d->n ), false );
        if ( !d->m || d->m->deleted() )
            error( No, "No such mailbox: " + d->n );
        else if ( Session::activeSessions( d->m ) )
            error( No, "Mailbox is in use" );
        else if ( d->m->synthetic() )
            error( No, d->m->name() + " does not really exist anyway" );
        else if ( d->m == imap()->user()->inbox() )
            error( No, "Cannot delete INBOX" );
        if ( !ok() )
            return;
        d->p = new Permissions( d->m, imap()->user(), this );
        d->q = new Query( "select count(*)::int as undeletable "
                          "from deleted_messages "
                          "where mailbox=$1", this );
        d->q->bind( 1, d->m->id() );
        d->q->execute();
    }

    if ( !d->p->ready() || !d->q->done() )
        return;

    if ( !d->p->allowed( Permissions::DeleteMailbox ) ||
         !d->p->allowed( Permissions::DeleteMessages ) ||
         !d->p->allowed( Permissions::Expunge ) )
    {
        // XXX should make this more fine-grained. and there's a
        // race with APPEND/COPY too. (See notes.)
        error( No, "Not allowed to delete mailbox " + d->m->name() );
        return;
    }

    if ( !d->t ) {
        uint undeletable = 0;

        Row * r = d->q->nextRow();
        if ( d->q->failed() || !r )
            error( No, "Could not determine if undeletable messages exist" );
        else
            undeletable = r->getInt( "undeletable" );

        if ( undeletable )
            error( No, "Cannot delete mailbox: " + fn( undeletable ) +
                   " undeletable messages exist" );

        if ( !ok() )
            return;

        d->t = new Transaction( this );
        if ( d->m->remove( d->t ) == 0 ) {
            error( No, "Cannot delete mailbox " + d->m->name() );
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

    OCClient::send( "mailbox " + d->m->name().quoted() + " deleted" );

    finish();
}
