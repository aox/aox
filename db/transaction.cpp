#include "transaction.h"

#include "database.h"
#include "query.h"
#include "event.h"
#include "list.h"


class TransactionData {
public:
    TransactionData()
        : db( 0 ), state( Transaction::Inactive )
    {}

    Database *db;
    Transaction::State state;
    List< Query > queries;
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


/*! Sets this Transaction's state to \a s.
*/

void Transaction::setState( State s )
{
    d->state = s;
}


/*! Returns the state of this Transaction, which may be Inactive (if it
    has not yet been begun), Executing, Completed, or Failed.
*/

Transaction::State Transaction::state() const
{
    return d->state;
}


/*! Returns true only if this Transaction has failed, and false if it
    succeeded, or is in progress.
*/

bool Transaction::failed() const
{
    return d->state == Failed;
}


/*! Returns true only if this Transaction has either succeeded or
    failed, and false if it is still awaiting completion.
*/

bool Transaction::done() const
{
    return d->state == Completed || d->state == Failed;
}


/*! Enqueues the query \a q within this transaction.
    The BEGIN will be sent before the first such query.
*/

void Transaction::enqueue( Query *q )
{
    q->setState( Query::Submitted );
    q->setTransaction( this );
    d->queries.append( q );
}


/*! Executes the queries enqueue()d so far.
*/

void Transaction::execute()
{
    List< Query >::Iterator it( d->queries.first() );
    while ( it )
        d->db->enqueue( it++ );
    d->db->execute();
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
    enqueue( q );
    execute();
}
