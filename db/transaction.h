// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef TRANSACTION_H
#define TRANSACTION_H

class Query;
class String;
class Database;
class EventHandler;


class Transaction {
public:
    Transaction( EventHandler *, Database * = 0 );

    enum State { Inactive, Executing, Completed, Failed };
    void setState( State );
    State state() const;
    bool failed() const;
    bool done() const;

    String error() const;
    void setError( const String & );

    void enqueue( Query * );
    void execute();
    void rollback();
    void commit();

private:
    class TransactionData *d;
};


#endif
