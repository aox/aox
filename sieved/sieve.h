// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVE_H
#define SIEVE_H

#include "global.h"
#include "list.h"


class String;
class Address;
class Message;
class Mailbox;
class SieveAction;


class Sieve
    : public Garbage
{
public:
    Sieve();

    void setSender( Address * );
    void addRecipient( Address * );
    void setMessage( Message * );

    Address * sender() const;
    Address * recipient() const;

    void evaluate();
    bool succeeded( Address * );
    bool failed( Address * );
    String result( Address * );
    bool done() const;

    List<Mailbox> * mailboxes() const;
    List<Address> * forwarded() const;
    bool rejected() const;

    void addAction( SieveAction * );

private:
    class SieveData * d;
};

#endif
