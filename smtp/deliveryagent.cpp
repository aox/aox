// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "deliveryagent.h"

#include "log.h"
#include "scope.h"
#include "query.h"
#include "transaction.h"
#include "mailbox.h"
#include "message.h"


class DeliveryAgentData
    : public Garbage
{
public:
    DeliveryAgentData()
        : log( 0 ), mailbox( 0 ), uid( 0 ), t( 0 )
    {}

    Log * log;
    Mailbox * mailbox;
    uint uid;
    Transaction * t;
};


/*! \class DeliveryAgent deliveryagent.h
    Responsible for attempting to deliver a queued message and updating
    the corresponding row in the deliveries table.
*/

/*!  Constructs an empty

*/

DeliveryAgent::DeliveryAgent( Mailbox * mailbox, uint uid )
    : d( new DeliveryAgentData )
{
    d->mailbox = mailbox;
    d->uid = uid;
    d->log = new Log( Log::SMTP );
}


/*!

*/

void DeliveryAgent::execute()
{
    Scope x( d->log );
    if ( !d->t ) {
        d->t = new Transaction( this );
        d->t->execute();
    }

    //...
}
