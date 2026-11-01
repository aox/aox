// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef MAILBOXGET_H
#define MAILBOXGET_H

#include "method.h"
#include "list.h"
#include "integerset.h"


class Mailbox;


class MailboxGet
    : public JmapMethod
{
public:
    MailboxGet( EventHandler *, class User *, class Json * );

    void execute();

private:
    void collect( Mailbox * );
    class Json * mailbox( Mailbox * );

private:
    class MailboxGetData * d;
};


#endif
