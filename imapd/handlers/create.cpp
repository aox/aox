#include "create.h"

#include "imap.h"
#include "query.h"
#include "mailbox.h"


/*! \class Create create.h
    Creates a new mailbox (RFC 3501, §6.3.3)
*/

/*! \reimp */

Create::Create()
    : q( 0 )
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
        else if ( m->synthetic() ) {
            // We don't allow synthetic mailboxes to be created. Yet.
            // I'll think about it after we know how to manage the tree.
        }
        else if ( m->deleted() ) {
            q = new Query( "update mailboxes set "
                           "deleted=0,uidvalidity=uidvalidity+1 where id=$1",
                           this );
            q->bind( 1, m->id() );
        }
        else if ( !m ) {
            q = new Query( "insert into mailboxes (name) values ($1)", this );
            q->bind( 1, mbx );
        }

        if ( q )
            q->execute();
    }

    if ( q && !q->done() )
        return;

    if ( !q || q->failed() ) {
        error( No, "Couldn't create " + name );
        finish();
        return;
    }

    // We need to tell the OCServer what we did.

    finish();
}
