#include "transaction.h"

#include "database.h"
#include "query.h"
#include "event.h"


class TransactionData {
public:
    TransactionData()
        : db( 0 ), state( Transaction::Inactive )
    {}

    Database *db;
    Transaction::State state;
};


/*! \class Transaction transaction.h
    Represents a single database transaction.
*/


/*! Creates a new Transaction object.
*/

Transaction::Transaction()
    : d( new TransactionData )
{
    d->db = Database::handle();
}


/*! Returns the state of this Transaction, which may be Inactive (if it
    has not yet been begun), Executing, Completed, or Failed.
*/

Transaction::State Transaction::state() const
{
    return d->state;
}


/*! Sets this Transaction's state to \a s.
*/

void Transaction::setState( State s )
{
    d->state = s;
}


/*! Returns true only if this Transaction has either succeeded or
    failed, and false if it is still awaiting completion.
*/

bool Transaction::done() const
{
    return d->state == Completed || d->state == Failed;
}


/*! Executes the query \a q within this transaction.
    The BEGIN will be sent before the first such query.
*/

void Transaction::execute( Query *q )
{
    q->setTransaction( this );
    d->db->submit( q );
}


/*! Ends this transaction.
*/

void Transaction::end()
{
    class CommitHandler
        : public EventHandler
    {
    private:
        Transaction *tr;

    public:
        CommitHandler( Transaction *t ):
            EventHandler(), tr( t )
        {}

        void execute() {
            tr->setState( Transaction::Completed );
        }
    };

    Query *q = new Query( "commit", new CommitHandler( this ) );
    q->setTransaction( this );
    d->db->submit( q );
}
