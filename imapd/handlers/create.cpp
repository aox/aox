#include "create.h"

#include "list.h"
#include "imap.h"
#include "query.h"
#include "mailbox.h"


/*! \class Create create.h
    Creates a new mailbox (RFC 3501, §6.3.3)

    The mailboxes table contains an entry for each deliverable mailbox
    that has ever existed in the database. This class either inserts a
    new entry, or resurrects a previously deleted one.
*/

/*! \reimp */

Create::Create()
    : q( 0 ), q2( 0 )
{
}


/*! \reimp */

void Create::parse()
{
    space();
    name = astring();
    end();
}


/*! \reimp */

void Create::execute()
{
    if ( !q ) {
        String mbx = imap()->mailboxName( name );
        Mailbox *m = Mailbox::find( name, true );

        if ( name.lower() == "inbox" ) {
            // We don't need to test this, because the user's INBOX must
            // exist, and cannot be deleted.
        }
        else if ( !m ) {
            // If we are creating a mailbox that has never existed, we
            // need to insert a row into mailboxes, then fetch its id,
            // and create a suitably-named UID sequence for it.
            List< Query > l;

            q = new Query( "insert into mailboxes (name) values ($1)", this );
            q->bind( 1, mbx );
            l.append( q );

            q2 = new Query( "select currval('mailbox_ids')::integer as id",
                            this );
            l.append( q2 );

            Database::query( &l );

        }
        else if ( m->id() == 0 ) {
            // We don't allow synthetic mailboxes to be created. Yet.
            // I'll think about it after we know how to manage the tree.
        }
        else if ( m->deleted() ) {
            q = new Query( "update mailboxes set deleted=0,"
                           "uidvalidity=uidvalidity+1 where id=$1", this );
            q->bind( 1, m->id() );
            q->execute();
        }
    }

    if ( ( q && !q->done() ) || ( q2 && !q2->done() ) )
        return;

    if ( !q || q->failed() ) {
        error( No, "Couldn't create " + name );
        finish();
        return;
    }

    // If we created a new entry, we have to create a new sequence for
    // it. We *really* assume that sequence creation cannot fail.
    if ( q2 ) {
        uint id = *q2->nextRow()->getInt( "id" );
        q2 = 0;
        q = new Query( "create sequence mailbox_" +
                       String::fromNumber( id ), this );
        q->execute();
        return;
    }
    
    // We need to tell the OCServer what we did.

    finish();
}
