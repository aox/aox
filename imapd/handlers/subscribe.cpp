// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "subscribe.h"

#include "imap.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"


/*! \class Subscribe subscribe.h
    Adds a mailbox to the subscription list (RFC 3501 section 6.3.6)

    This class implements both Subscribe and Unsubscribe. The required
    mode is set by the constructor, and is used by execute() to decide
    what to do.
*/

/*! Creates a subscribe handler in mode \a n, which may be Add or Remove
    according to the desired function. The default is Add.
*/

Subscribe::Subscribe( Mode n )
    : mode( n ), selected( false ), q( 0 ), m( 0 )
{}


/*! \class Unsubscribe subscribe.h
    Removes a mailbox from the subscription list (RFC 3501 section 6.3.7)

    This class inherits from Subscribe, and calls its constructor with
    a subscription mode of Subscribe::Remove. It has no other code.
*/

Unsubscribe::Unsubscribe()
    : Subscribe( Subscribe::Remove )
{
}


void Subscribe::parse()
{
    space();
    name = astring();
    end();
    if ( ok() )
        log( "Subscribe " + name );
}


void Subscribe::execute()
{
    // We check if the user has already subscribed to the mailbox, and
    // depending on what we want, add the mailbox to the subscriptions
    // table, remove it, or do nothing.

    if ( !q ) {
        m = Mailbox::find( imap()->mailboxName( name ) );
        if ( !m ) {
            error( No, "Can't subscribe to non-existent mailbox " + name );
            finish();
            return;
        }

        q = new Query( "select id from subscriptions where owner=$1 "
                       "and mailbox=$2", this );
        q->bind( 1, imap()->user()->id() );
        q->bind( 2, m->id() );
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
            q->bind( 1, imap()->user()->id() );
            q->bind( 2, m->id() );
        }
        else if ( mode == Remove && q->rows() == 1 ) {
            int id = q->nextRow()->getInt( "id" );
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
