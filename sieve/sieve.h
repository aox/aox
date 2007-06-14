// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVE_H
#define SIEVE_H

#include "event.h"
#include "list.h"


class User;
class String;
class Address;
class Message;
class Mailbox;
class SieveAction;
class SieveScript;


class Sieve
    : public EventHandler
{
public:
    Sieve();

    void execute();

    void setSender( Address * );
    void addRecipient( Address *, Mailbox *, User *, SieveScript * = 0 );
    void setMessage( Message * );

    void setPrefix( Address *, const String & );

    Address * sender() const;
    Address * recipient() const;

    void evaluate();
    bool rejected( Address * ) const;
    bool succeeded( Address * ) const;
    bool failed( Address * ) const;
    String error( Address * ) const;
    String error() const;
    bool done() const;
    bool ready() const;

    List<SieveAction> * actions( const Address * ) const;

    List<Mailbox> * mailboxes() const;
    List<Address> * forwarded() const;
    bool rejected() const;

    void addAction( SieveAction * );

private:
    class SieveData * d;
};

#endif
