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
    DeliveryAgent( uint, EventHandler * );

    void execute();

    bool done() const;
    bool delivered() const;

    void setClient( SmtpClient * );
    SmtpClient * client() const;

private:
    class DeliveryAgentData * d;

    Query * fetchDelivery( uint );
    Message * fetchMessage( uint );
    Query * fetchSender( uint );
    Query * fetchRecipients( uint );
    DSN * createDSN( Message *, Query *, Query * );
    void expireRecipients( DSN * );
    void logDelivery( DSN * );
    Injector * injectBounce( DSN * );
    uint updateDelivery( uint, DSN * );
};


#endif
