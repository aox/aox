// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DELIVERYAGENT_H
#define DELIVERYAGENT_H

#include "event.h"


class Mailbox;


class DeliveryAgent
    : public EventHandler
{
public:
    DeliveryAgent( Mailbox *, uint, EventHandler * );

    void execute();

    bool done() const;
    bool delivered() const;
    const String status() const;

private:
    class DeliveryAgentData * d;
};


#endif
