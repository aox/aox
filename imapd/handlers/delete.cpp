// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "delete.h"

#include "imap.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "occlient.h"
#include "permissions.h"
#include "transaction.h"


class DeleteData
    : public Garbage
{
public:
    DeleteData(): m( 0 ), t( 0 ), p( 0 ) {}

    String n;
    Mailbox * m;
    Transaction * t;
    Permissions * p;
};


/*! \class Delete delete.h
    Deletes an existing mailbox (RFC 3501 section 6.3.4)

    (Really deletes? What happens to the mail there?)
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
}


void Delete::execute()
{
    if ( !d->m ) {
        d->m = Mailbox::obtain( imap()->mailboxName( d->n ), false );
        if ( !d->m || d->m->deleted() )
            error( No, "No such mailbox: " + d->n );
        else if ( d->m->synthetic() )
            error( No, d->m->name() + " does not really exist anyway" );
        else if ( d->m == imap()->user()->inbox() )
            error( No, "Cannot delete INBOX" );
        if ( !ok() )
            return;
        d->p = new Permissions( d->m, imap()->user(), this );
    }

    if ( !d->p->ready() )
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

    // the database will check that m isn't someone's inbox

    if ( !d->t ) {
        d->t = new Transaction( this );
        if ( d->m->remove( d->t ) == 0 ) {
            error( No, "Can't delete mailbox " + d->m->name() );
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
