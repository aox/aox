// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DELIVERYAGENT_H
#define DELIVERYAGENT_H

#include "event.h"


class DSN;
class Query;
class Mailbox;
class Message;
class Injector;
class SmtpClient;


class DeliveryAgent
    : public EventHandler
{
public:
    DeliveryAgent( SmtpClient *, Mailbox *, uint, EventHandler * );

    void execute();

    bool done() const;
    bool delivered() const;

private:
    class DeliveryAgentData * d;

    Query * fetchDeliveries( Mailbox *, uint );
    Message * fetchMessage( Mailbox *, uint );
    Query * fetchSender( uint );
    Query * fetchRecipients( uint );
    DSN * createDSN( Message *, Query *, Query * );
    void expireRecipients( DSN * );
    void logDelivery( DSN * );
    Injector * injectBounce( DSN * );
    uint updateDelivery( uint, DSN * );
};


#endif
