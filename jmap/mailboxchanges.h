// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef MAILBOXCHANGES_H
#define MAILBOXCHANGES_H

#include "method.h"


class Mailbox;


class MailboxChanges
    : public JmapMethod
{
public:
    MailboxChanges( EventHandler *, class User *, class Json * );

    void execute();

private:
    void collect( Mailbox * );

private:
    class MailboxChangesData * d;
};


#endif
