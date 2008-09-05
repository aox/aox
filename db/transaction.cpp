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
    String savepoint;
    uint children;
    bool submittedCommit;
    bool submittedBegin;
    EventHandler *owner;
    Database *db;

    List< Query > *queries;

    Query * failedQuery;
    String error;
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
    back. If \a ev is 0 (the default), the new Transaction shares its
    parent's owner; otherwise the given owner is used instead.

    ...
*/

Transaction * Transaction::subTransaction( EventHandler * ev )
{
    if ( d->state == Blocked )
        return 0;

    d->children++;
    d->state = Blocked;

    if ( ev == 0 )
        ev = d->owner;

    Transaction * t = new Transaction( ev );
    t->d->parent = this;
    t->d->savepoint = d->savepoint + "_" + fn( d->children );

    return t;
}


/*! Returns a pointer to the parent of this Transaction, which will be 0
    if this is not a subTransaction(). */

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

void Transaction::setError( Query * query, const String &s )
{
    if ( d->state == Failed || !d->owner )
        return;

    Scope x( d->owner->log() );
    if ( query && query->canFail() )
        log( s, Log::Debug );
    else
        log( s, Log::Error );
    d->failedQuery = query;
    d->error = s;
    d->state = Failed;
    if ( !query )
        return;
    String qs = query->string();
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

String Transaction::error() const
{
    return d->error;
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

    if ( d->parent ) {
        Query * q = new Query( "rollback to " + d->savepoint, d->owner );
        enqueue( q );
        q->setTransaction( d->parent );
        d->parent->setState( Executing );
        setState( Completed );
    }
    else {
        enqueue( new Query( "rollback", d->owner ) );
    }
    d->submittedCommit = true;

    execute();
}


class SubtransactionTrampoline
    : public EventHandler
{
private:
    Transaction * t;
    Query * q;

public:
    SubtransactionTrampoline( Transaction * transaction, Query * query )
        : t( transaction ), q( query )
    {}

    void execute ()
    {
        if ( !q->done() )
            return;

        if ( !t->failed() && q->failed() )
            t->setError( q, q->error() );

        if ( !t->failed() )
            t->setState( Transaction::Completed );
        t->parent()->setState( Transaction::Executing );
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

    if ( d->parent ) {
        Query * q = new Query( "release savepoint " + d->savepoint, 0 );
        q->setOwner( new SubtransactionTrampoline( this, q ) );
        enqueue( q );
        q->setTransaction( d->parent );
    }
    else {
        enqueue( new Query( "commit", 0 ) );
    }
    d->submittedCommit = true;

    execute();
}


/*! Executes the queries enqueued so far. */

void Transaction::execute()
{
    if ( !d->queries || d->queries->isEmpty() )
        return;

    List< Query >::Iterator it( d->queries );
    while ( it ) {
        it->setState( Query::Submitted );
        ++it;
    }

    if ( d->db ) {
        // if we've a handle already, it can work
        d->db->processQueue();
    }
    else if ( !d->submittedBegin ) {
        // if not, we ask Database to give us one, either through our
        // parent or directly.
        Query * begin;
        if ( d->parent ) {
            begin = new Query( "savepoint " + d->savepoint, d->owner );
            d->parent->enqueue( begin );
            begin->setTransaction( this );
            d->parent->execute();
        }
        else {
            begin = new Query( "begin", 0 );
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
}
