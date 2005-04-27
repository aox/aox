// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "query.h"

#include "scope.h"
#include "string.h"
#include "database.h"
#include "event.h"
#include "stringlist.h"
#include "transaction.h"
#include "loop.h"
#include "log.h"


class QueryData {
public:
    QueryData()
        : state( Query::Inactive ),
          transaction( 0 ), owner( 0 ), totalRows( 0 ), startup( false ),
          canFail( false )
    {}

    Query::State state;

    String name;
    String query;
    SortedList< Query::Value > values;
    List< int > types;

    Transaction *transaction;
    EventHandler *owner;
    List< Row > rows;
    uint totalRows;

    String description;
    String error;

    bool startup;
    bool canFail;
};


/*! \class Query query.h
    This class represents a single database query.

    A Query is typically created by (or for, or with) a EventHandler,
    has parameter values bound to it with bind(), and is execute()d
    (or enqueue()d as part of a Transaction).

    Once the Query is executed, the Database informs its owner() of any
    interesting events (e.g. the arrival of results, timeouts, failures,
    or successful completion) by calling notify(). The Query's state()
    reflects its progress, as do the done() and failed() functions.

    Each Query contains a list of rows (Row objects) of data received
    in response to itself. The hasResults() function tells you if
    there are any rows, which can be read and removed from the list by
    calling nextRow().  The query keeps track of the total number of
    rows() received.

    Most queries are normal queries, but some can be startup queries
    (see setStartUpQuery()), ie. queries that are necessary for the
    server to start up. If such a query fails, Query logs a disaster.

    A Query can be part of a Transaction.
*/


/*! Constructs a new empty Query handled by \a ev.
    (This form is provided for use by subclasses.)
*/

Query::Query( EventHandler *ev )
    : d( new QueryData )
{
    d->owner = ev;
}


/*! Constructs a Query for \a ev containing the SQL statement \a s. */

Query::Query( const String &s, EventHandler *ev )
    : d( new QueryData )
{
    d->query = s;
    d->owner = ev;
}


/*! Constructs a Query for \a ev from the prepared statement \a ps. */

Query::Query( const PreparedStatement &ps, EventHandler *ev )
    : d( new QueryData )
{
    d->name = ps.name();
    d->query = ps.query();
    d->owner = ev;
}


/*! \fn Query::~Query()

    This virtual destructor exists only so that subclasses can define
    their own.
*/


/*! Returns the state of this object, which may be one of the following:

    Inactive: This query has not yet been submitted to the Database.
    Submitted: The query has been submitted to the Database.
    Executing: The query has been sent to the server.
    Succeeded: The query completed successfully.
    Failed: The query has failed.
*/

Query::State Query::state() const
{
    return d->state;
}


static uint startup;

/*! Sets the state of this object to \a s.
    The initial state of each Query is Inactive, and the Database changes
    it to indicate the query's progress.
*/

void Query::setState( State s )
{
    if ( d->startup && !done() &&
         ( s == Completed || s == Failed ) )
        ::startup--;
    if ( d->startup && s == Failed )
        Loop::shutdown();
    d->state = s;
}


/*! Returns true only if this Query has either succeeded or failed, and
    false if it is still awaiting completion.
*/

bool Query::done() const
{
    return ( d->state == Query::Failed ||
             d->state == Query::Completed );
}


/*! Returns true if this Query failed, and false if it succeeded, or if
    it is not yet done().
*/

bool Query::failed() const
{
    return d->state == Query::Failed;
}


/*! Notifies this query that it's necessary to start the server if \a
    necessary is true, and that it's an ordinary query if \a necessary
    is false.

    The isStartingUp() function returns true if at least one such
    query is unfinished.
*/

void Query::setStartUpQuery( bool necessary )
{
    if ( done() )
        ;
    else if ( necessary && !d->startup )
        ::startup++;
    else if ( d->startup && !necessary )
        ::startup--;
    d->startup = necessary;
}


/*! Returns true if this Query is a startup query, that is, if the
    server hasn't finished initializing until this Query is complete.
*/

bool Query::isStartUpQuery() const
{
    return d->startup;
}


/*! Returns true if at least one startup query is queued or running,
    and false if all such queries have finished.
*/

bool Query::isStartingUp()
{
    return ::startup > 0;
}


/*! Returns true only if allowFailure() has been called for this query,
    signifying that this query is known to run the risk of failure (e.g.
    the Injector's "insert into bodyparts..." query may violate a unique
    constraint).

    This function exists only so that Postgres can avoid logging
    unimportant errors.
*/

bool Query::canFail() const
{
    return d->canFail;
}


/*! If this function is called before execute(), Postgres will not log
    an error if the Query fails. The query continues to be processed
    as it would be otherwise.
*/

void Query::allowFailure()
{
    d->canFail = true;
}


/*! Returns a pointer to the Transaction that this Query is associated
    with, or 0 if this Query is self-contained.
*/

Transaction *Query::transaction() const
{
    return d->transaction;
}


/*! Sets this Query's parent transaction to \a t.
*/

void Query::setTransaction( Transaction *t )
{
    d->transaction = t;
}


/*! Binds the integer value \a s to the parameter \a n of this Query.
*/

void Query::bind( uint n, int s )
{
    bind( n, fn( s ) );
}


/*! \overload
    Binds the String value \a s to the parameter \a n of this Query in
    the specified format \a f (Binary or Text; Text by default).
*/

void Query::bind( uint n, const String &s, Format f )
{
    Value *v = new Value( n, s, f );
    d->values.insert( v );
}


/*! \overload
    Binds NULL to the parameter \a n of this Query.
*/

void Query::bindNull( uint n )
{
    d->values.insert( new Value( n ) );
}


/*! This function submits this Query to the Database for processing. The
    owner() of the query will be informed of any activity via notify().
*/

void Query::execute()
{
    Database::submit( this );
}


/*! Returns the name of a prepared statement that represents this Query,
    or an empty string if the Query was not created from a previously
    prepared statement.
*/

String Query::name() const
{
    return d->name;
}


/*! This virtual function is expected to return the complete SQL query
    as a string. Subclasses may reimplement this function to compose a
    query from individual parameters, rather than requiring the entire
    query to be specified during construction.

    This function is intended for use by the Database.
*/

String Query::string() const
{
    return d->query;
}


/*! Returns a pointer to the list of Values bound to this Query.
*/

List< Query::Value > *Query::values() const
{
    return &d->values;
}


/*! Returns a pointer to the list of pre-specified parameter types for
    this query.
*/

List< int > *Query::types() const
{
    return &d->types;
}


/*! Appends the type \a n to the list of types to pre-specify. */

void Query::appendType( int n )
{
    d->types.append( new int( n ) );
}


/*! Returns a pointer to the owner of this Query, as specified during
    construction.
*/

EventHandler *Query::owner() const
{
    return d->owner;
}


/*! The Database calls this function to inform the owner() of this Query
    about any interesting activity, such as the arrival of rows from the
    server, or the completion of the query.
*/

void Query::notify()
{
    // Transactions may create COMMIT/ROLLBACK queries without handlers.
    if ( d->owner )
        d->owner->execute();
}


/*! Returns a description of this query and its parameters, if any, that
    is suitable for logging and debugging. (The description is generated
    and stored the first time this function is called, and later calls
    just return the old value.)
*/

String Query::description()
{
    if ( d->description.isEmpty() ) {
        StringList p;

        int i = 0;
        List< Query::Value >::Iterator v( values()->first() );
        while ( v ) {
            i++;

            String r;
            int n = v->length();
            if ( n == -1 )
                r = "NULL";
            else if ( n <= 16 && v->format() != Query::Binary )
                r = "'" + v->data() + "'";
            else
                r = "...{" + fn( n ) + "}";
            p.append( fn(i) + "=" + r );
            ++v;
        }

        d->description.append( "\"" + string() + "\"" );
        if ( i > 0 )
            d->description.append( " (" + p.join(",") + ")" );
    }

    return d->description;
}


/*! This function returns an error message if the Query has failed(),
    and an empty string otherwise.
*/

String Query::error() const
{
    return d->error;
}


/*! Stores the error message \a s in response to this Query, and sets
    the Query state to Failed. If the Query belongs to a Transaction,
    the Transaction::state() is set to Failed too.

    This function is intended for use by the Database.
*/

void Query::setError( const String &s )
{
    d->error = s;
    setState( Failed );
    if ( d->transaction )
        d->transaction->setError( s );
}


/*! Returns the number of rows received from the server in response to
    this Query.
*/

uint Query::rows() const
{
    return d->totalRows;
}


/*! Returns true if any rows of data received in response to this Query
    have not yet been read and removed by calling nextRow().
*/

bool Query::hasResults() const
{
    return d->rows.count() > 0;
}


/*! For each Row \a r received in response to this query, the Database
    calls this function to append it to the list of results.
*/

void Query::addRow( Row *r )
{
    d->rows.append( r );
    d->totalRows++;
}


/*! This function returns a pointer to the first unread Row of results
    received in response to this Query, and removes it from the list.
    If there are no rows left to read, it returns 0.
*/

Row *Query::nextRow()
{
    List< Row >::Iterator r( d->rows.first() );
    if ( !r )
        return 0;
    return d->rows.take( r );
}


/*! \class Row query.h
    Represents a single row of data retrieved from the Database.

    The Database creates Row objects for every row of data received, and
    populates them with the appropriate Column objects before appending
    them to the originating Query.

    Users of Query can retrieve each row in turn with Query::nextRow(),
    and use the getInt()/getString()/etc. accessor functions, each of
    which takes a column name, to retrieve the values of each column
    in the Row.

    XXX: This class is still somewhat "under construction".
*/


/*! Creates a row of data with \a num columns from the array \a c. */

Row::Row( uint num, Column *c )
    : n( num ), columns( c )
{
    // One could build a Dict< Column > here to supplant findColumn, but
    // for a handful of columns, who cares?
}


/*! Returns true if the column at index \a i is NULL or does not exist,
    and false in all other cases.
*/

bool Row::isNull( uint i ) const
{
    if ( columns[i].length == -1 || badFetch( i ) )
        return true;
    return false;
}


/*! \overload
    As above, but returns true only if the column named \a f is NULL.
*/

bool Row::isNull( const String &f ) const
{
    int i = findColumn( f );
    if ( i < 0 )
        return false;
    return isNull( i );
}


/*! Returns the boolean value of the column at index \a i if it exists
    and is NOT NULL, and false otherwise.
*/

bool Row::getBoolean( uint i ) const
{
    if ( badFetch( i, Column::Boolean ) )
        return false;
    return columns[i].value[0];
}


/*! \overload
    As above, but returns the boolean value of the column named \a f.
*/

bool Row::getBoolean( const String &f ) const
{
    int i = findColumn( f );
    if ( i < 0 )
        return false;
    return getBoolean( i );
}


/*! Returns the integer value of the column at index \a i if it exists
    and is NOT NULL, and 0 otherwise.
*/

int Row::getInt( uint i ) const
{
    if ( badFetch( i, Column::Integer ) )
        return 0;

    int n = 0;
    Column *c = &columns[i];

    switch ( c->length ) {
    case 1:
        n = c->value[0];
        break;

    case 2:
        n = c->value[0] << 8 | c->value[1];
        break;

    case 4:
        n = c->value[0] << 24 | c->value[1] << 16 |
            c->value[2] << 8  | c->value[3];
        break;

    default:
        /*
        log( Log::Disaster,
             "Integer field " + c->name + " has invalid length " +
             fn( c->length ) );
        */
        break;
    }

    return n;
}


/*! \overload
    As above, but returns the integer value of the column named \a f.
*/

int Row::getInt( const String &f ) const
{
    int i = findColumn( f );
    if ( i < 0 )
        return 0;
    return getInt( i );
}


/*! Returns the string value of the column at index \a i if it exists
    and is NOT NULL, and an empty string otherwise.
*/

String Row::getString( uint i ) const
{
    if ( badFetch( i, Column::Bytes ) )
        return "";
    return columns[i].value;
}


/*! \overload
    As above, but returns the string value of the column named \a f.
*/

String Row::getString( const String &f ) const
{
    int i = findColumn( f );
    if ( i < 0 )
        return "";
    return getString( i );
}


/*! This private function returns the index of the column named \a f, if
    if exists, and -1 if it does not.
*/

int Row::findColumn( const String &f ) const
{
    uint i = 0;
    while ( i < n ) {
        if ( columns[i].name == f )
            return i;
        i++;
    }

    log( "Unknown column " + f, Log::Error );
    return -1;
}


/*! This private method returns false only if the column at index \a i
    exists, is NOT NULL, and (optionally) if its type matches \a t. If
    not, it logs a disaster and returns true.
*/

bool Row::badFetch( uint i, Column::Type t ) const
{
    String s;

    if ( i >= n )
        s = "No column at index #" + fn( i );
    else if ( columns[i].length == -1 )
        s = "Column " + columns[i].name + " is NULL.";
    else if ( t != Column::Unknown &&
              columns[i].type != t )
        s = "Column " + columns[i].name + " is of type " +
            Column::typeName( columns[i].type ) + ", not " +
            Column::typeName( t );
    else
        return false;

    log( s, Log::Error );
    return true;
}



/*! \class PreparedStatement query.h
    This class represents an SQL prepared statement.

    A PreparedStatement has a name() and an associated query(). Its only
    purpose is to be used to construct Query objects. Each object has a
    unique name.
*/


static int prepareCounter = 0;


/*! Creates a PreparedStatement containing the SQL statement \a s, and
    generates a unique name for it.
*/

PreparedStatement::PreparedStatement( const String &s )
    : n( fn( prepareCounter++ ) ), q( s )
{
}


/*! Returns the name of this PreparedStatement.
*/

String PreparedStatement::name() const
{
    return n;
}


/*! Returns the text of this PreparedStatement.
*/

String PreparedStatement::query() const
{
    return q;
}


/*! \class Column query.h
    This class represents a single column in a row.
    Has no member functions or useful documentation yet.
*/

/*! Returns the name of \a type, mostly for logging purposes. */

String Column::typeName( Column::Type type )
{
    String n;
    switch( type ) {
    case Unknown:
        n = "unknown";
        break;
    case Boolean:
        n = "boolean";
        break;
    case Integer:
        n = "integer";
        break;
    case Bytes:
        n = "string";
        break;
    }
    return n;
}

