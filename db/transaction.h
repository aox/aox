#ifndef TRANSACTION_H
#define TRANSACTION_H

class Query;
class EventHandler;


class Transaction {
public:
    Transaction( EventHandler * );

    enum State { Inactive, Executing, Completed, Failed };
    void setState( State );
    State state() const;
    bool failed() const;
    bool done() const;

    void enqueue( Query * );
    void execute();
    void rollback();
    void commit();

private:
    class TransactionData *d;
};


#endif
