// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DELIVERYAGENT_H
#define DELIVERYAGENT_H

#include "global.h"


class DeliveryAgent
    : public EventHandler
{
public:
    DeliveryAgent( Mailbox *, uid );

    void execute();

private:
    class DeliveryAgentData * d;
};


#endif
