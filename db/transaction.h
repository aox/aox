#ifndef TRANSACTION_H
#define TRANSACTION_H

class Query;


class Transaction {
public:
    Transaction();

    enum State { Inactive, Executing, Completed, Failed };
    State state() const;
    void setState( State );
    bool done() const;

    void execute( Query * );
    void end();

private:
    class TransactionData *d;
};


#endif
