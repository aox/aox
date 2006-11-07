// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "list.h"


class Query;
class String;
class Database;
class EventHandler;


class Transaction
    : public Garbage
{
public:
    Transaction( EventHandler * );
    void setDatabase( Database * );

    enum State { Inactive, Executing, Completed, Failed };
    void setState( State );
    State state() const;
    bool failed() const;
    bool done() const;

    void setError( Query *, const String & );
    String error() const;

    Query * failedQuery() const;

    void enqueue( Query * );
    void execute();
    void rollback();
    void commit();

    List< Query > *enqueuedQueries() const;
    EventHandler * owner() const;
    void notify();

private:
    class TransactionData *d;
};


#endif
