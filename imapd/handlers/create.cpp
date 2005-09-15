// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "create.h"

#include "imap.h"
#include "mailbox.h"
#include "occlient.h"
#include "permissions.h"
#include "transaction.h"


class CreateData
    : public Garbage
{
public:
    CreateData(): t( 0 ), p( 0 ), m( 0 ) {}
    String name;
    Transaction * t;
    Permissions * p;
    Mailbox * m;
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
        d->m = Mailbox::obtain( d->name, true );
        if ( d->m )
            d->t = d->m->create( this, imap()->user() );
        else
            error( No, d->name + " is not a valid mailbox name" );
        if ( !d->t )
            error( No, d->name + " already exists" );
    }

    if ( d->t && d->t->failed() )
        error( No, "Database error: " + d->t->error() );

    if ( !d->t || !d->t->done() || !ok() )
        return;

    finish();

    OCClient::send( "mailbox " + d->m->name().quoted() + " new" );
}
