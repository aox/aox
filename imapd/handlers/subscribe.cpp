/*! \class Subscribe subscribe.h
    Adds a mailbox to the subscription list (RFC 3501, §6.3.6)

    This class implements both Subscribe and Unsubscribe. The required
    mode is set by the constructor, and used in execute().
*/


/*! \class Unsubscribe subscribe.h
    Removes a mailbox from the subscription list (RFC 3501, §6.3.7)

    This class inherits from Subscribe, and calls its constructor with
    a subscription mode of Subscribe::Remove. It has no other code.
*/


#include "subscribe.h"

#include "imap.h"
#include "query.h"


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
    if ( !q ) {
        q = new Query( "select id from subscriptions where "+
                       String( "owner=" ) + String::fromNumber( imap()->uid() ) +
                       "and mailbox='"+ m +"'", this );
        q->submit();
        return;
    }

    error( No, "unimplemented command" );
    setState( Finished );
}
