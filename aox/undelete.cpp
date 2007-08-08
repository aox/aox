// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "undelete.h"

#include "transaction.h"
#include "occlient.h"
#include "mailbox.h"
#include "query.h"

class UndeleteData
    : public Garbage
{
public:
    UndeleteData()
        : uid( 0 ), q( 0 ), m( 0 ), t( 0 )
    {}

    String mailbox;
    uint uid;
    Query * q;
    Mailbox * m;
    Transaction * t;
};


/*! \class Undelete Undelete.h
    This class handles the "aox undelete" command.
*/

Undelete::Undelete( StringList * args )
    : AoxCommand( args ), d( new UndeleteData )
{
}


void Undelete::execute()
{
    if ( d->mailbox.isEmpty() ) {
        bool ok = false;
        parseOptions();
        d->mailbox = next();
        d->uid = next().number( &ok );
        end();

        if ( d->mailbox.isEmpty() )
            error( "No mailbox name supplied." );

        if ( d->uid < 1 || !ok )
            error( "No valid UID supplied." );

        database( true );
        Mailbox::setup( this );
    }

    if ( !choresDone() )
        return;

    if ( !d->q ) {
        d->m = Mailbox::obtain( d->mailbox, false );
        if ( !d->m )
            error( "No mailbox named '" + d->mailbox + "'" );

        d->q = new Query( "select * from deleted_messages where mailbox=$1 "
                          "and uid=$2", this );
        d->q->bind( 1, d->m->id() );
        d->q->bind( 2, d->uid );
        d->q->execute();
    }

    if ( !d->t ) {
        if ( !d->q->done() )
            return;

        Row * r = d->q->nextRow();
        if ( d->q->failed() || !r )
            error( "Couldn't find deleted message with uid " + fn( d->uid ) +
                   " in mailbox '" + d->mailbox + "'." );

        d->t = new Transaction( this );
        d->q = new Query( "delete from deleted_messages where mailbox=$1 "
                          "and uid=$2", this );
        d->q->bind( 1, d->m->id() );
        d->q->bind( 2, d->uid );
        d->t->enqueue( d->q );

        d->q = new Query( "delete from flags where mailbox=$1 and uid=$2 and "
                          "flag=1", this );
        d->q->bind( 1, d->m->id() );
        d->q->bind( 2, d->uid );
        d->t->enqueue( d->q );

        d->q = new Query( "update mailboxes set uidvalidity=uidvalidity+1 "
                          "where id=$1", this );
        d->q->bind( 1, d->m->id() );
        d->t->enqueue( d->q );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        error( "Couldn't undelete message: " + d->t->error() );
    }
    else {
        // XXX: What should I send? There's no occlient message right
        // now to say that the UIDVALIDITY of a mailbox has changed,
        // and sending "new" to force a refresh seems very evil.
        OCClient::send( "mailbox " + d->m->name().quoted() + " new" );
    }

    finish();
}
