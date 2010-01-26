// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "list.h"


class Query;
class EString;
class Database;
class EventHandler;


class Transaction
    : public Garbage
{
public:
    Transaction( EventHandler * );
    void setDatabase( Database * );

    enum State { Inactive, Executing, Completed, RolledBack, Failed };
    void setState( State );
    State state() const;
    bool blocked() const;
    bool failed() const;
    bool done() const;

    void clearError();
    void setError( Query *, const EString & );
    EString error() const;

    Query * failedQuery() const;

    void enqueue( Query * );
    void enqueue( const char * );
    void enqueue( const EString & );
    void execute();
    void rollback();
    void restart();
    void commit();

    List< Query > *enqueuedQueries() const;
    EventHandler * owner() const;
    void notify();

    Transaction * subTransaction( EventHandler * );
    Transaction * parent() const;

    void finalizeTransaction( Query * );

private:
    class TransactionData *d;
};


#endif
