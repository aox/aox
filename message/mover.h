// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef MOVER_H
#define MOVER_H

#include "global.h"
#include "event.h"
#include "estring.h"
#include "ustring.h"

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

    bool done() const;
    Query * report() const;
    int64 modseq() const;

    static Mailbox * homeOf( Mailbox * );
    static Mailbox * specialUse( Mailbox *, const EString & );
    static Query * fillAllMail( Transaction *, const UString &,
                                uint, int64, uint = 0 );

private:
    class MoverData * d;
};


#endif
