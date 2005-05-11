// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "create.h"

#include "imap.h"
#include "query.h"
#include "mailbox.h"
#include "permissions.h"


class CreateData
{
public:
    CreateData(): q( 0 ), p( 0 ) {}
    String name;
    Query * q;
    Permissions * p;
};


/*! \class Create create.h
    Creates a new mailbox (RFC 3501, §6.3.3)

    The mailboxes table contains an entry for each deliverable mailbox
    that has ever existed in the database. This class either inserts a
    new entry, or resurrects a previously deleted one.
*/

Create::Create()
    : d( new CreateData )
{
}


void Create::parse()
{
    space();
    String name( astring() );
    end();
    if ( name.lower() == "inbox" )
        error( No, "INBOX always exists" );
    d->name = imap()->mailboxName( name );
}


void Create::execute()
{
    if ( !d->p ) {
        Mailbox * m = Mailbox::closestParent( d->name );
        if ( !m )
            error( No, "Syntax error in mailbox name: " + d->name );
        else
            d->p = new Permissions( m, imap()->user(), this );
        if ( d->p && !d->p->allowed( Permissions::CreateMailboxes ) )
            error( No, "Cannot create mailboxes under " + m->name() );
    }
    if ( ok() && !d->q ) {
        Mailbox * m = Mailbox::find( d->name, true );

        if ( !m || m->synthetic() ) {
            d->q = new Query( "insert into mailboxes (name) values ($1)",
                              this );
            d->q->bind( 1, d->name );
        }
        else if ( m->deleted() ) {
            d->q = new Query( "update mailboxes set deleted=0 where id=$1",
                              this );
            d->q->bind( 1, m->id() );
        }
        else {
            error( No, d->name + " already exists" );
            return;
        }

        d->q->execute();
    }

    if ( d->q && d->q->failed() )
        error( No, "Database error: " + d->q->error() );

    if ( !d->q || !d->q->done() || !ok() )
        return;

    finish();

    // XXX We need to tell the OCServer what we did.
}
