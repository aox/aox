// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "create.h"

#include "imap.h"
#include "mailbox.h"
#include "permissions.h"
#include "transaction.h"


class CreateData
{
public:
    CreateData(): t( 0 ), p( 0 ) {}
    String name;
    Transaction * t;
    Permissions * p;
};


/*! \class Create create.h
    Creates a new mailbox (RFC 3501 section 6.3.3)

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
    if ( ok() && !d->t ) {
        Mailbox * m = Mailbox::find( d->name, true );
        if ( !m )
            m = new Mailbox( d->name );
        if ( !m->synthetic() && !m->deleted() ) {
            error( No, d->name + " already exists" );
            return;
        }

        d->t = m->create( this, imap()->user() );
    }

    if ( d->t && d->t->failed() )
        error( No, "Database error: " + d->t->error() );

    if ( !d->t || !d->t->done() || !ok() )
        return;

    finish();

    // XXX We need to tell the OCServer what we did.
}
