// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
        : state( Transaction::Inactive ), parent( 0 ), activeChild( 0 ),
          children( 0 ),
          submittedCommit( false ), submittedBegin( false ),
          committing( false ),
          owner( 0 ), db( 0 ), queries( 0 ), failedQuery( 0 )
    {}

    Transaction::State state;
    Transaction * parent;
    Transaction * activeChild;
    EString savepoint;
    uint children;
    bool submittedCommit;
    bool submittedBegin;
    bool committing;
    EventHandler * owner;
    Database *db;

    List< Query > *queries;

    Query * failedQuery;
    EString error;

    class CommitBouncer
        : public EventHandler
    {
    public:
        CommitBouncer( Transaction * t ): q( 0 ), me( t ) {}

        void execute () {
            me->finalizeTransaction( q );
        }

        Query * q;

    private:
        Transaction * me;
    };

    class BeginBouncer
        : public EventHandler
    {
    public:
        BeginBouncer( Transaction * t ): q( 0 ), me( t ) {}

        void execute () {
            me->finalizeBegin( q );
        }

        Query * q;

    private:
        Transaction * me;
    };
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
    execute() or commit() it.

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
        TransactionData::BeginBouncer * b 
            = new TransactionData::BeginBouncer( this );
        b->q = new Query( "begin", b );
        b->q->setTransaction( this );
        d->queries->append( b->q );
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
    return d->state == Completed ||
        d->state == Failed ||
        d->state == RolledBack;
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
    Scope x( d->owner->log() );
    if ( d->submittedCommit ) {
        q->setError( "Query submitted after commit/rollback: " + q->string() );
        return;
    }
    if ( !d->queries )
        d->queries = new List< Query >;
    q->setTransaction( this );
    d->queries->append( q );
    q->setState( Query::Submitted );
}


/*! \overload

    This version creates a new Query based on \a text and enqueues it.
    It does not give the caller a chance to set the query's owner or to
    bind parameters, so it's most useful for things like DDL.
*/

void Transaction::enqueue( const char * text )
{
    enqueue( new Query( text, 0 ) );
}


/*! \overload

    This version creates a new Query based on \a text and enqueues it.
    Limitations as for the const char * variant above.
*/

void Transaction::enqueue( const EString & text )
{
    enqueue( new Query( text, 0 ) );
}


/*! Issues a ROLLBACK to abandon the Transaction, and fails any
    queries that still haven't been sent to the server. The owner is
    notified of completion.
*/

void Transaction::rollback()
{
    if ( state() == Completed ) {
        log( "rollback() called after commit" );
        return;
    }

    if ( !d->submittedBegin ) {
        d->submittedBegin = true;
        d->submittedCommit = true;
        setState( RolledBack );
        return;
    }

    // hm... is dropping these queries really worth it? it does reduce
    // log clutter.
    List<Query>::Iterator i( d->queries );
    while ( i ) {
        i->setError( "Transaction rolled back, query aborted." );
        ++i;
    }
    d->queries = 0;

    if ( d->parent ) {
        // if we're a subtransaction, then what we need to do is roll
        // back to the savepoint, then release it...
        enqueue( new Query( "rollback to " + d->savepoint, 0 ) );
        TransactionData::CommitBouncer * cb = 
            new TransactionData::CommitBouncer( this );
        Query * q = new Query( "release savepoint " + d->savepoint, cb );
        cb->q = q;
        enqueue( q );
        execute();
    }
    else {
        TransactionData::CommitBouncer * cb = 
            new TransactionData::CommitBouncer( this );
        Query * q = new Query( "rollback", cb );
        cb->q = q;
        enqueue( q );
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


/*! Handles whatever needs to happen when a BEGIN or SAVEPOINT
    finishes; \a q is the begin query.
*/

void Transaction::finalizeBegin( Query * q )
{
    if ( q->failed() ) {
        if ( d->parent && d->parent->d->activeChild == this )
            d->parent->d->activeChild = 0;
        if ( d->parent )
            setError( q, "Savepoint failed" );
        else
            setError( q, "Begin failed (huh?)" );
        List<Query>::Iterator i( d->queries );
        while ( i ) {
            i->setError( "Transaction unable to start" );
            ++i;
        }
        notify();
        if ( d->parent )
            d->parent->execute();
    }
    else {
        setState( Executing );
        execute();
    }
}


/*! This private function handles whatever needs to happen when a
    transaction finishes; \a q is the finishing query (typically
    commit, rollback or release savepoint). There are three cases:

    If the commit/rollback works, we restart the parent.

    If a subtransaction is rolled back and the rollback fails, we're
    in real trouble.

    If a subtransaction should commit and the release savepoint fails,
    we roll the subtransaction back and should eventually hand over to
    the parent transaction.
*/

void Transaction::finalizeTransaction( Query * q )
{
    if ( !q->failed() ) {
        if ( d->committing )
            setState( Completed );
        else
            setState( RolledBack );
        notify();
        if ( d->parent ) {
            if ( d->parent->d->activeChild == this )
                d->parent->d->activeChild = 0;
            parent()->execute();
        }
    }
    else if ( d->committing ) {
        d->committing = false;
        d->submittedCommit = false;
        rollback();
        setError( q, q->error() );
        notify();
    }
    else {
        setError( q, q->error() );
        notify();
        // a rollback failed. how is this even possible? what to do?
    }
}


/*! Issues a COMMIT to complete the Transaction (after sending any
    queries that were already enqueued). The owner is notified when
    the Transaction completes.

    For a failed() Transaction, commit() is equivalent to rollback().
*/

void Transaction::commit()
{
    if ( d->submittedCommit )
        return;

    if ( !d->submittedBegin &&
         ( !d->queries || d->queries->isEmpty() ) ) {
        d->submittedBegin = true;
        d->submittedCommit = true;
        setState( Completed );
        return;
    }

    if ( d->parent ) {
        TransactionData::CommitBouncer * cb = 
            new TransactionData::CommitBouncer( this );
        Query * q = new Query( "release savepoint " + d->savepoint, cb );
        cb->q = q;
        enqueue( q );
    }
    else {
        TransactionData::CommitBouncer * cb = 
            new TransactionData::CommitBouncer( this );
        Query * q = new Query( "commit", cb );
        cb->q = q;
        enqueue( q );
    }
    d->submittedCommit = true;
    d->committing = true;

    execute();
}


/*! Executes the queries enqueued so far. */

void Transaction::execute()
{
    if ( !d->queries || d->queries->isEmpty() )
        return;

    // we may need to set up queries in order to start
    if ( !d->submittedBegin ) {
        // if not, we have to obtain one
        bool parentDone = false;
        Transaction * p = d->parent;
        while ( p && !parentDone ) {
            if ( p->d->committing || p->done() )
                parentDone = true;
            p = p->d->parent;
        }
        if ( parentDone ) {
            List<Query>::Iterator i( d->queries );
            while ( i ) {
                i->setError( "Transaction started after parent finished" );
                ++i;
            }
            return;
        }
        d->submittedBegin = true;
        if ( d->parent ) {
            // we ask to borrow our parent's handle
            TransactionData::BeginBouncer * b
                = new TransactionData::BeginBouncer( this );
            b->q = new Query( "savepoint " + d->savepoint, b );
            d->parent->enqueue( b->q );
            b->q->setTransaction( this );
            d->parent->execute();
        }
        else {
            // if we're an ordinary transaction, we queue a begin in
            // the open pool...
            TransactionData::BeginBouncer * b
                = new TransactionData::BeginBouncer( this );
            b->q = new Query( "begin", b );
            // ... and tell the db to shift control to us.
            b->q->setTransaction( this );
            Database::submit( b->q );
        }
    }

    // if we have a database, poke it
    Transaction * t = this;
    while ( t->d->parent )
        t = t->d->parent;
    if ( t->d->db )
        t->d->db->processQueue();
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


/*! Returns a pointer to the currently active subtransaction, or to
    this transaction is no subtransaction is active.
*/

Transaction * Transaction::activeSubTransaction()
{
    Transaction * t = this;
    while ( t->d->parent )
        t = t->d->parent;
    while ( t->d->activeChild )
        t = t->d->activeChild;
    return t;
}


/*! Removes all queries that can be sent to the server from the front
    of the queue and returns them. May change activeSubTransaction()
    as a side effect, if the last query starts a subtransaction.
    
    The returned pointer is never null, but the list may be empty.
*/

List< Query > * Transaction::submittedQueries()
{
    List<Query> * r = new List<Query>();

    Transaction * t = activeSubTransaction();

    if ( !t->d->queries )
        return r;

    bool last = false;
    while ( !t->d->queries->isEmpty() && !last ) {
        Query * q = t->d->queries->shift();
        r->append( q );
        // if we change to a subtransaction, we start picking queries
        // there, and don't send anything more yet
        if ( q->transaction() != t ) {
            t->d->activeChild = q->transaction();
            last = true;
        }
        // if the query is a copy, we have to let it finish before we
        // can send more queries.
        if ( q->inputLines() ) {
            last = true;
        }
    }

    return r;
}
