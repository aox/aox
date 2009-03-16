// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "transaction.h"

#include "eventloop.h"
#include "database.h"
#include "query.h"
#include "event.h"
#include "scope.h"
#include "list.h"


class TransactionData
    : public Garbage
{
public:
    TransactionData()
        : state( Transaction::Inactive ), parent( 0 ), children( 0 ),
          submittedCommit( false ), submittedBegin( false ),
          owner( 0 ), db( 0 ), queries( 0 ), failedQuery( 0 )
    {}

    Transaction::State state;
    Transaction * parent;
    EString savepoint;
    uint children;
    bool submittedCommit;
    bool submittedBegin;
    EventHandler *owner;
    Database *db;

    List< Query > *queries;

    Query * failedQuery;
    EString error;
};


/*! \class Transaction transaction.h
    This class manages a single database transaction.

    A Transaction accepts a series of queries via enqueue(), and sends
    them to the server when execute() is called. It ends when commit()
    or rollback() is called. Its state() indicates its progress.

    A Transaction commandeers a database handle when you ask it to
    execute its queries, and keeps it until commit() or rollback(). If
    you give it a database handle using setDatabase(), it'll use that
    instead of asking for one.

    The Transaction can also provide subtransactions; these are
    implemented using SAVEPOINT, RELEASE SAVEPOINT for commit() and
    ROLLBACK TO SAVEPOINT for restart() and rollback.

    When you call subTransaction(), you get a new Transaction which
    isn't yet active. The subtransaction becomes active when you
    execute() or commit() it. At that point it blocks its parent, and
    the parent remains blocked() until the subtransaction commits or
    rolls back.

    It's possible to use a Transaction for any combination of
    subtransactions and queries. A Query enqueued in the parent waits
    until any active subtransaction finishes. Similarly, if you
    execute() one subtransaction while another is active, the new
    subtransaction will wait.
*/


/*! Creates a new Transaction owned by \a ev (which MUST NOT be 0). */

Transaction::Transaction( EventHandler *ev )
    : d( new TransactionData )
{
    d->owner = ev;
    d->savepoint = "s";
}


/*! Returns a pointer to a new Transaction that is subordinate to the
    current one, but which can be independently committed or rolled
    back.

    The returned subtransaction isn't active yet; if you call
    execute() or commit() on it, it will attempt to take over its
    parent's Database and do its work. If you don't call execute() on
    the subtransaction before commit() on the parent, then the
    subtransaction cannot be used.

    The subtransaction will notify \a ev when it succeeds or fails.
*/

Transaction * Transaction::subTransaction( EventHandler * ev )
{
    d->children++;

    if ( ev == 0 )
        ev = d->owner;

    Transaction * t = new Transaction( ev );
    t->d->parent = this;
    t->d->savepoint = d->savepoint + "_" + fn( d->children );

    return t;
}


/*! Returns a pointer to the parent of this Transaction, which will be 0
    if this is not a subTransaction().
*/

Transaction * Transaction::parent() const
{
    return d->parent;
}


/*! Sets this Transaction's Database handle to \a db.

    This function is used by the Database when the BEGIN is processed.
*/

void Transaction::setDatabase( Database *db )
{
    d->db = db;

    if ( d->queries )
        return;
    d->queries = new List<Query>;
    if ( !d->submittedBegin ) {
        Query * begin = new Query( "begin", 0 );
        begin->setTransaction( this );
        d->queries->append( begin );
        d->submittedBegin = true;
    }
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


/*! Clears this Transaction's error state (as set with setError()) and
    places it in Executing state. Used to support savepoints.
*/

void Transaction::clearError()
{
    d->failedQuery = 0;
    d->error.truncate();
    d->state = Executing;

}


/*! Sets this Transaction's state() to Failed, and records the error
    message \a s. The first \a query that failed is recorded, and is
    returned by failedQuery() (but \a query may be 0 if the failure
    was not specific to a query within the transaction).
*/

void Transaction::setError( Query * query, const EString &s )
{
    if ( d->state == Failed || !d->owner )
        return;

    Scope x( d->owner->log() );
    if ( query && query->canFail() )
        log( s, Log::Debug );
    else if ( d->parent )
        log( s );
    else
        log( s, Log::Error );
    d->failedQuery = query;
    d->error = s;
    d->state = Failed;
    if ( !query )
        return;
    EString qs = query->string();
    if ( qs.startsWith( "select " ) && qs.contains( " from " ) )
        qs = qs.section( " from ", 1 ) + "...";
    else if ( qs.startsWith( "insert into " ) && qs.contains( " values " ) )
        qs = qs.section( " values ", 1 ) + "...";
    else if ( qs.startsWith( "update " ) && qs.contains( " set " ) )
        qs = qs.section( " set ", 1 ) + "...";
    else if ( qs.length() > 32 )
        qs = qs.mid( 0, 32 ) + "...";
    d->error.append( " (query: " );
    d->error.append( qs );
    d->error.append( ")" );
}


/*! Returns the error message associated with this Transaction. This
    value is meaningful only if the Transaction has failed().
*/

EString Transaction::error() const
{
    return d->error;
}


/*! Returns true if this transaction is executing, but blocked by a
    subtransaction, and false in all other cases.
*/

bool Transaction::blocked() const
{
    if ( !d->db )
        return false;
    return d->db->blocked( this );
}


/*! Returns a pointer to the first Query in this transaction that
    failed. The return value is meaningful only if the transaction
    has failed, and 0 otherwise.

    The return value may also be 0 if the Transaction has been forcibly
    rolled back by the Postgres class because of a timeout (such as the
    caller forgetting to ever commit() the Transaction).

    This function is useful in composing error messages.
*/

Query * Transaction::failedQuery() const
{
    return d->failedQuery;
}


/*! Enqueues the query \a q within this Transaction, to be sent to the
    server only after execute() is called. The BEGIN is automatically
    enqueued before the first query in a Transaction.
*/

void Transaction::enqueue( Query *q )
{
    if ( d->submittedCommit ) {
        q->setError( "Query submitted after commit/rollback: " + q->string() );
        return;
    }
    if ( !d->queries )
        d->queries = new List< Query >;
    q->setTransaction( this );
    d->queries->append( q );
}


/*! Issues a ROLLBACK to abandon the Transaction, and fails any
    queries that still haven't been sent to the server. The owner is
    notified of completion.
*/

void Transaction::rollback()
{
    if ( d->submittedCommit ) {
        log( "rollback() called after commit/rollback" );
        return;
    }

    // hm... is dropping these queries really worth it? it does reduce
    // log clutter.
    List<Query>::Iterator i( d->queries );
    while ( i ) {
        if ( i->state() == Query::Inactive ||
             i->state() == Query::Submitted ) {
            i->setError( "Transaction rolled back, query aborted." );
            d->queries->take( i );
        }
        else {
            ++i;
        }
    }

    if ( !d->submittedBegin ) {
        // if we haven't started, stopping is no work
    }
    else if ( d->parent ) {
        // if we're a subtransaction, then what we need to do is roll
        // back to the savepoint, then release it...
        Query * q = new Query( "rollback to " + d->savepoint, 0 );
        enqueue( q );
        q = new Query( "release savepoint " + d->savepoint, d->owner );
        enqueue( q );
        // ... and make the "release savepoint" shift control to the
        // parent.
        q->setTransaction( d->parent );
        execute();
        // rollback() completes this transaction
        setState( Completed );
        d->parent->notify();
    }
    else {
        enqueue( new Query( "rollback", d->owner ) );
        // shouldn't this set the state to Completed too? XXX
        execute();
    }
    d->submittedCommit = true;

}


/*! Unwinds whatever the subtransaction has done and restarts it.
*/

void Transaction::restart()
{
    if ( d->submittedCommit ) {
        log( "restart() called after commit/rollback" );
        return;
    }
    else if ( !d->submittedBegin ) {
        return;
    }
    else if ( !d->parent ) {
        d->queries->clear();
        enqueue( new Query( "rollback", d->owner ) );
        d->submittedBegin = false;
    }
    else {
        d->queries->clear();
        enqueue( new Query( "rollback to " + d->savepoint, d->owner ) );
        setState( Executing );
    }
    execute();
}


class SubtransactionTrampoline
    : public EventHandler
{
private:
    Transaction * t;
    Query * q;

public:
    SubtransactionTrampoline( const EString & sp, Transaction * transaction )
        : t( transaction ), q ( 0 )
    {
        q = new Query( "release savepoint " + sp, this );
        t->enqueue( q );
        // this statement has to shift control to the parent transaction
        q->setTransaction( t->parent() );
    }

    void execute ()
    {
        if ( !q->done() )
            return;

        if ( !t->failed() && q->failed() )
            // if releasing the savepoint failed, so did the subtransaction
            t->setError( q, q->error() );

        if ( t->failed() ) {
            // if the subtransaction failed, it couldn't be committed,
            // and in that case, the parent fails, too.
            t->parent()->setError( t->failedQuery(), t->error() );
        }
        else {
            // if the subtransaction works, all is fine.
            t->setState( Transaction::Completed );
            // the parent may have a queue it needs to service.
            t->parent()->execute();
        }
        t->notify();
    }
};


/*! Issues a COMMIT to complete the Transaction (after sending any
    queries that were already enqueued). The owner is notified when
    the Transaction completes.

    For a failed() Transaction, commit() is equivalent to rollback().
*/

void Transaction::commit()
{
    if ( d->submittedCommit )
        return;

    if ( d->parent )
        (void)new SubtransactionTrampoline( d->savepoint, this );
    else
        enqueue( new Query( "commit", 0 ) );
    d->submittedCommit = true;

    execute();
}


/*! Executes the queries enqueued so far. */

void Transaction::execute()
{
    if ( !d->queries || d->queries->isEmpty() )
        return;
    if ( d->db && d->db->blocked( this ) )
        return;

    // we can send all the queries that are simply ours
    List< Query >::Iterator it( d->queries );
    while ( it && it->transaction() == this ) {
        it->setState( Query::Submitted );
        ++it;
    }

    // after that, we can send a single query that'll shift control to
    // a subtransaction or to our parent.
    if ( it && it->transaction() && it->transaction()->parent() == this ) {
        // shift to subtransaction
        it->setState( Query::Submitted );
    }
    else if ( it && it->transaction() && parent() == it->transaction() ) {
        // shift to parent
        it->setState( Query::Submitted );
    }

    if ( d->db ) {
        // if we've a handle already, it can work
        d->db->processQueue();
    }
    else if ( !d->submittedBegin ) {
        // if not, we have to obtain one
        Query * begin;
        if ( d->parent ) {
            // we ask to borrow our parent's handle
            begin = new Query( "savepoint " + d->savepoint, 0 );
            d->parent->enqueue( begin );
            begin->setTransaction( this );
            d->parent->execute();
            if ( begin->failed() ) {
                // if the parent has failed or succeeded, or perhaps
                // for other reasons, then we couldn't borrow the
                // handle, so we need to fail all our queries.
                setError( begin, "Savepoint failed" );
                List<Query>::Iterator i( d->queries );
                while ( i ) {
                    i->setError( "Failed due to earlier query" );
                    ++i;
                }
            }
        }
        else {
            // if we're an ordinary transaction, we queue a begin in
            // the open pool...
            begin = new Query( "begin", 0 );
            // ... and tell the db to shift control to us.
            begin->setTransaction( this );
            Database::submit( begin );
        }
        d->submittedBegin = true;
    }
}


/*! Returns a pointer to the List of queries that have been enqueue()d
    within this Transaction, but not yet processed by the database. The
    pointer will not be 0 after the first query has been enqueued. The
    state of each Query will be Submitted if execute() has been called
    after it was enqueued. Queries are removed from the list once they
    have been processed.

    This function is meant for use by the Database, in order to retrieve
    the Queries that need processing.
*/

List< Query > *Transaction::enqueuedQueries() const
{
    return d->queries;
}


/*! Returns a pointer to the owner of this query, as specified to the
    constructor. Transactions MUST have owners, so this function may
    not return 0. There is an exception: If the owner is severely
    buggy, notify() may set the owner to 0 to avoid segfaults.
*/

EventHandler * Transaction::owner() const
{
    return d->owner;
}


/*! Notifies the owner of this Transaction about a significant event. */

void Transaction::notify()
{
    if ( !d->owner )
        return;
    Scope s( d->owner->log() );
    try {
        d->owner->execute();
    }
    catch ( Exception e ) {
        d->owner = 0; // so we can't get close to a segfault again
        if ( e == Invariant ) {
            setError( 0,
                      "Invariant failed "
                      "while processing Transaction::notify()" );
            rollback();
            List<Connection>::Iterator i( EventLoop::global()->connections() );
            while ( i ) {
                Connection * c = i;
                ++i;
                Log * l = Scope::current()->log();
                while ( l && l != c->log() )
                    l = l->parent();
                if ( c->type() != Connection::Listener && l ) {
                    Scope x( l );
                    ::log( "Invariant failed; Closing connection abruptly",
                           Log::Error );
                    EventLoop::global()->removeConnection( c );
                    c->close();
                }
            }
        }
        else {
            throw e;
        }
    }
    if ( done() && d->parent &&
         d->parent->d->queries &&
         d->parent->d->queries->isEmpty() )
        d->parent->notify();
}
