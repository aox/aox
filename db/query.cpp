#include "query.h"

#include "scope.h"
#include "string.h"
#include "database.h"
#include "event.h"
#include "transaction.h"
#include "log.h"


class QueryData {
public:
    QueryData()
        : type( Query::Execute ), state( Query::Inactive ),
          transaction( 0 ), owner( 0 ), totalRows( 0 ), startup( false )
    {}

    Query::Type type;
    Query::State state;

    String name;
    String query;
    SortedList< Query::Value > values;

    Transaction *transaction;
    EventHandler *owner;
    List< Row > rows;
    uint totalRows;

    String error;

    bool startup;
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


/*! Returns the type of this Query, which may be any of Begin, Execute,
    Commit, or Rollback (as defined in Query::Type).
*/

Query::Type Query::type() const
{
    return d->type;
}


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
    if ( s == d->state )
        return;
    if ( ( s == Completed || s == Failed ) && !done() )
        ::startup--;
    d->state = s;
    String action;
    switch( s ) {
    case Inactive:
        action = "Deactivated";
        break;
    case Submitted:
        action = "Submitted";
        break;
    case Executing:
        action = "Executing";
        break;
    case Completed:
        action = "Completed";
        break;
    case Failed:
        action = "Failed";
        break;
    }
    if ( d->startup && failed() )
        log( Log::Disaster, "Necessary startup query failed: " + string() );
    else
        log( Log::Debug, action + " query " + string() );
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
    Database::query( this );
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
    if ( !d->owner )
        return;
    
    Scope( d->owner->arena() );
    d->owner->execute();
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
    log( Log::Debug, "Database error message: " + s );

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
    List< Row >::Iterator r = d->rows.first();

    if ( r )
        return d->rows.take( r );
    return 0;
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


/*! Creates an empty row of data. */

Row::Row()
{
}


/*! This helper function is used by Postgres::composeRow() to append a
    Column \a cv to this Row of data, as it parses a DataRow response.
*/

void Row::append( Row::Column *cv )
{
    columns.append( cv );
}


/*! This private function returns a pointer to the Column named \a field
    in this Row, or 0 if there is no such column.
*/

List< Row::Column >::Iterator Row::findColumn( const String &field ) const
{
    List< Column >::Iterator c = columns.first();
    while ( c && c->name != field )
        c++;
    return c;
}


/*! This helper function logs an error message complaining that a
    search for \a field either did not succeed or that the \a result
    was not of the right \a type.
*/

void Row::logDisaster( Column * result, const String & field,
                       Database::Type type ) const
{
    if ( !result )
        log( Log::Disaster, "Schema mismatch: Did not find Field " + field +
             " (of type " + Database::typeName( type ) + ")" );
    else
        log( Log::Disaster, "Schema mismatch: Field " +
             field + " has type " + Database::typeName( result->type ) +
             ", while the caller expects " + 
             Database::typeName( type ) );
}


/*! If this Row contains a Column of string type named \a field, this
    function returns its String value, and an empty string if the
    field is NULL, unknown, or not a string.
*/

String Row::getString( const String &field ) const
{
    List< Column >::Iterator c = findColumn( field );

    if ( c && c->type == Database::Bytes )
        return c->value;

    logDisaster( c, field, Database::Bytes );
    return "";
}


/*! If this Row contains a Column of integer type named \a field, this
    function returns its value. It returns 0 if the field is NULL,
    unknown, or not an integer.
*/

int Row::getInt( const String &field ) const
{
    List< Column >::Iterator c = findColumn( field );

    if ( !c || c->type != Database::Integer ) {
        logDisaster( c, field, Database::Integer );
        return 0;
    }
    else if ( c->length == -1 ) {
        log( Log::Error, "Integer Field " + field + " is unexpectedly null" );
        return 0;
    }

    int n;
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
        log( Log::Error, "Integer field " + field + " has invalid length " +
             fn( c->length ) );
        break;
    }
    return n;
}


/*! If this Row contains a Column of boolean type named \a field, this
    function returns its value. It returns false iif the field is NULL,
    unknown, or not a boolean value.
*/

bool Row::getBoolean( const String &field ) const
{
    List< Column >::Iterator c = findColumn( field );

    if ( !c || c->type != Database::Boolean ) {
        logDisaster( c, field, Database::Boolean );
        return false;
    }
    else if ( c->length == -1 ) {
        log( Log::Error, "Boolean Field " + field + " is unexpectedly null" );
        return false;
    }

    if ( c->value[0] != 0 )
        return true;
    return false;
}


/*! Returns true if \a field exists and is null, and false in all
    other cases. Logs a disaster if \a field does not exist.
*/

bool Row::null( const String & field ) const
{
    List< Column >::Iterator c = findColumn( field );

    if ( !c )
        log( Log::Disaster, "Did not find Field " + field );
    else if ( c->length == -1 )
        return true;

    return false;
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
