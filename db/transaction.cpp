#include "transaction.h"

#include "database.h"
#include "query.h"
#include "event.h"
#include "list.h"


class TransactionData {
public:
    TransactionData()
        : db( 0 ), owner( 0 ), state( Transaction::Inactive )
    {}

    Database *db;
    EventHandler *owner;
    Transaction::State state;
};


/*! \class Transaction transaction.h
    This class manages a single database transaction.

    A Transaction acquires a Database::handle() upon creation, making it
    available to users through enqueue() and execute(). The commit() and
    rollback() functions end a Transaction. The state() of a transaction
    indicates its progress.

    The Database sends a BEGIN before the first Query enqueue()d through
    a Transaction, and subsequently refuses to accept queries from other
    sources until the transaction has ended.
*/


/*! Creates a new Transaction object owned by \a ev. */

Transaction::Transaction( EventHandler *ev )
    : d( new TransactionData )
{
    d->db = Database::handle();
    d->owner = ev;
}


/*! Sets this Transaction's state to \a s, which must be one of Inactive
    (if it has not yet been started), Executing, Completed, or Failed.
*/

void Transaction::setState( State s )
{
    d->state = s;
}


/*! Returns the current state of this Transaction. */

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


/*! Enqueues the query \a q within this transaction. The BEGIN will be
    sent by the database before the first such enqueue()d query.
*/

void Transaction::enqueue( Query *q )
{
    q->setTransaction( this );
    d->db->enqueue( q );
}


/*! Executes all the queries enqueue()d so far. */

void Transaction::execute()
{
    d->db->execute();
}


/*! Abandons this Transaction. */

void Transaction::rollback()
{
    Query *q = new Query( "rollback", d->owner );
    q->setTransaction( this );
    d->db->enqueue( q );
    d->db->execute();
}


/*! Commits this Transaction. */

void Transaction::commit()
{
    Query *q = new Query( "commit", d->owner );
    q->setTransaction( this );
    d->db->enqueue( q );
    d->db->execute();
}
