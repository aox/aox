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
    CreateData(): t( 0 ), p( 0 ), m( 0 ), parent( 0 ) {}
    String name;
    Transaction * t;
    Permissions * p;
    Mailbox * m;
    Mailbox * parent;
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
    d->name = mailboxName( name );
    log( "Create " + name + " (" + d->name + ")" );
}


void Create::execute()
{
    if ( !d->p ) {
        d->parent = Mailbox::closestParent( d->name );
        if ( !d->parent ) {
            error( No, "Syntax error in mailbox name: " + d->name );
            return;
        }

        d->p = new Permissions( d->parent, imap()->user(), this );
    }

    if ( !d->p->ready() )
        return;

    if ( !d->p->allowed( Permissions::CreateMailboxes ) ) {
        error( No, "Cannot create mailboxes under " + d->parent->name() );
        return;
    }

    if ( !d->t ) {
        d->m = Mailbox::obtain( d->name, true );
        d->t = new Transaction( this );
        if ( !d->m ) {
            error( No, d->name + " is not a valid mailbox name" );
            return;
        }
        else if ( d->m->create( d->t, imap()->user() ) == 0 ) {
            error( No, d->name + " already exists" );
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

    OCClient::send( "mailbox " + d->m->name().quoted() + " new" );

    finish();
}
