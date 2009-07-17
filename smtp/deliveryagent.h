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

    Message * fetchMessage( uint );
    void createDSN();
    void expireRecipients( DSN * );
    void logDelivery( DSN * );
    Injector * injectBounce( DSN * );
    void updateDelivery();
    void restart();
};


#endif
