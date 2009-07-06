// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SIEVE_H
#define SIEVE_H

#include "event.h"
#include "list.h"


class Date;
class User;
class EString;
class UString;
class Address;
class Mailbox;
class SieveAction;
class SieveScript;
class Injectee;


class Sieve
    : public EventHandler
{
public:
    Sieve();

    void execute();

    void setSender( Address * );
    void addRecipient( Address *, Mailbox *, User *, SieveScript * );
    void addRecipient( Address *, EventHandler * );
    void addSubmission( Address * );
    void setMessage( Injectee *, Date * );

    Address * sender() const;
    Address * recipient() const;

    bool local( Address * ) const;

    void evaluate();
    bool rejected( Address * ) const;
    bool succeeded( Address * ) const;
    bool failed( Address * ) const;
    EString error( Address * ) const;
    EString error() const;
    bool softError() const;
    bool done() const;
    bool ready() const;
    bool injected() const;

    void act( EventHandler * );
    List<SieveAction> * actions( const Address * ) const;

    List<Mailbox> * mailboxes() const;
    List<Address> * forwarded() const;
    List<SieveAction> * vacations() const;
    bool rejected() const;

    void addAction( SieveAction * );

private:
    class SieveData * d;
};

#endif
