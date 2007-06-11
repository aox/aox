// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "deliveryagent.h"

#include "log.h"



/*!  Constructs an empty

*/

DeliveryAgent::DeliveryAgent( Mailbox * mailbox, uint uid )
    : d( new DeliveryAgentData )
{
    d->mailbox = mailbox;
    d->uid = uid;
    d->log = new Log( SMTP );
}


/*!

*/

void DeliveryAgent::execute()
{
    Scope x( d->log );
    if ( !d->t ) {
        d->t = new Transaction;
        d->recipients = new Query( "select for update" );

        d->t->execute();
    }

    //...
}
