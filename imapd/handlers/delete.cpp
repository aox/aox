// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "delete.h"

#include "imap.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "permissions.h"
#include "transaction.h"


class DeleteData
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
        d->m = Mailbox::obtain( imap()->mailboxName( d->n ) );
        if ( !d->m || d->m->deleted() )
            error( No, "No such mailbox: " + d->n );
        else if ( d->m->synthetic() )
            error( No, d->m->name() + " does not really exist anyway" );
        if ( d->m == imap()->user()->inbox() )
            error( No, "Cannot delete INBOX" );
        if ( !ok() )
            return;
    }

    if ( ok() && !d->p ) {
        d->p = new Permissions( d->m, imap()->user(), this );
        if ( !d->p->allowed( Permissions::DeleteMailbox ) ||
             !d->p->allowed( Permissions::DeleteMessages ) ||
             !d->p->allowed( Permissions::Expunge ) )
            error( No, "Not allowed to delete mailbox " + d->m->name() );
        // XXX should make this more fine-grained. and there's a
        // race with APPEND/COPY too.
    }


    // XXX: should check that m isn't someone's inbox

    if ( ok() && !d->t )
        d->t = d->m->remove( this );

    if ( d->t && d->t->failed() ) {
        error( No, "Database error during deletion: " + d->t->error() );
    }

    if ( !ok() || !d->t->done() )
        return;

    finish();

    // XXX We need to inform the OCServer about what we did.
}
