// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef MOVER_H
#define MOVER_H

#include "global.h"
#include "event.h"

class Transaction;
class IntegerSet;
class Mailbox;
class Query;
class User;


class Mover
    : public EventHandler
{
public:
    Mover( Transaction * within, User * user,
           Mailbox * from, Mailbox * to,
           const IntegerSet & messages,
           Query * middle,
           bool expunge = false, bool patient = true );

    void execute();

private:
    class MoverData * d;
};


#endif
