#include "query.h"

#include "scope.h"
#include "string.h"
#include "database.h"
#include "event.h"
#include "transaction.h"


class QueryData {
public:
    QueryData()
        : type( Query::Execute ), state( Query::Inactive ),
          transaction( 0 ), owner( 0 ), totalRows( 0 )
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
    This virtual destructor exists only so that subclasses can define their own.
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


/*! Sets the state of this object to \a s.
    The initial state of each Query is Inactive, and the Database changes
    it to indicate the query's progress.
*/

void Query::setState( State s )
{
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
    bind( n, String::fromNumber( s ) );
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
    d->state = Query::Failed;

    if ( d->transaction )
        d->transaction->setState( Transaction::Failed );
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

List< Row::Column >::Iterator Row::findColumn( const String &field )
{
    List< Column >::Iterator c = columns.first();
    while ( c && c->name != field )
        c++;
    return c;
}

/*! If this Row contains a Column of string type named \a field, this
    function returns a pointer to its String value, and 0 if the field
    is NULL, unknown, or not a string.

    XXX: This may need changing.
*/

String *Row::getString( const String &field )
{
    List< Column >::Iterator c = findColumn( field );

    if ( c && c->type == Database::Varchar && c->length != -1 )
        return new String( c->value );
    return 0;
}


/*! If this Row contains a Column of integer type named \a field, this
    function returns a pointer to its value, and 0 if the field is NULL,
    unknown, or not an integer.

    XXX: This may need changing. And what about uint/overflow?
*/

int *Row::getInt( const String &field )
{
    List< Column >::Iterator c = findColumn( field );

    if ( c && c->type == Database::Integer && c->length != -1 ) {
        bool ok;
        int n = String( c->value ).number( &ok );
        if ( ok )
            return new int( n );
    }
    return 0;
}


/*! If this Row contains a Column of boolean type named \a field, this
    function returns a pointer to its value, and 0 if the field is NULL,
    unknown, or not a boolean value.

    XXX: This may need changing.
*/

bool *Row::getBoolean( const String &field )
{
    List< Column >::Iterator c = findColumn( field );

    if ( c && c->type == Database::Boolean && c->length == 1 ) {
        String s = c->value;
        if ( s == "t" )
            return new bool( true );
        else if ( s == "f" )
            return new bool( false );
    }
    return 0;
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
    : n( String::fromNumber( prepareCounter++ ) ), q( s )
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
