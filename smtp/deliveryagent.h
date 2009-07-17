// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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

    uint messageId() const;

    void execute();

    bool working() const;
    bool delivered() const;

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
