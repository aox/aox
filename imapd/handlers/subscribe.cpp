#include "subscribe.h"

#include "imap.h"
#include "query.h"


/*! \class Subscribe subscribe.h
    Adds a mailbox to the subscription list (RFC 3501, §6.3.6)

    This class implements both Subscribe and Unsubscribe. The required
    mode is set by the constructor, and is used by execute() to decide
    what to do.
*/


/*! \class Unsubscribe subscribe.h
    Removes a mailbox from the subscription list (RFC 3501, §6.3.7)

    This class inherits from Subscribe, and calls its constructor with
    a subscription mode of Subscribe::Remove. It has no other code.
*/


/*! \reimp */

void Subscribe::parse()
{
    space();
    m = astring();
    end();
}


/*! \reimp */

void Subscribe::execute()
{
    // We check if the user has already subscribed to the mailbox, and
    // depending on what we want, add the mailbox to the subscriptions
    // table, remove it, or do nothing.

    if ( !q ) {
        q = new Query( "select id from subscriptions where owner=$1 "
                       "and mailbox=$2", this );
        q->bind( 1, imap()->uid() );
        q->bind( 2, m );
        q->execute();
        return;
    }

    if ( !q->done() )
        return;

    if ( q->failed() ) {
        error( No, "" );
        finish();
        return;
    }

    if ( !selected ) {
        selected = true;

        if ( mode == Add && q->rows() == 0 ) {
            q = new Query( "insert into subscriptions (owner, mailbox) "
                           "values ($1, $2)", this );
            q->bind( 1, imap()->uid() );
            q->bind( 2, m );
        }
        else if ( mode == Remove && q->rows() == 1 ) {
            int id = *q->nextRow()->getInt( "id" );
            q = new Query( "delete from subscriptions where id=$1", this );
            q->bind( 1, id );
        }
        else {
            // Do nothing if we're subscribing twice, or unsubscribing
            // without subscribing. (We don't report either an error.)
            q = 0;
        }

        if ( q ) {
            q->execute();
            return;
        }
    }

    finish();
}


/*! Constructs an Unsubscribe handler, which is a thin wrapper around
    functionality in Subscribe.
*/

Unsubscribe::Unsubscribe()
        : Subscribe( Subscribe::Remove )
{
}
