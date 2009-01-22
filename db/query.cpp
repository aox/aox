// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "query.h"

#include "log.h"
#include "utf.h"
#include "event.h"
#include "scope.h"
#include "string.h"
#include "ustring.h"
#include "database.h"
#include "eventloop.h"
#include "integerset.h"
#include "stringlist.h"
#include "transaction.h"


class QueryData
    : public Garbage
{
public:
    QueryData()
        : state( Query::Inactive ), format( Query::Text ),
          values( new Query::InputLine ), inputLines( 0 ),
          transaction( 0 ), owner( 0 ), totalRows( 0 ),
          canFail( false ), canBeSlow( false )
    {}

    Query::State state;
    Query::Format format;

    String name;
    String query;

    Query::InputLine *values;
    List< Query::InputLine > *inputLines;

    Transaction *transaction;
    EventHandler *owner;
    List< Row > rows;
    uint totalRows;

    String error;

    bool canFail;
    bool canBeSlow;
};


/*! \class Query query.h
    This class represents a single database query.

    A Query is typically created by (or for, or with) a EventHandler,
    has parameter values bound to it with bind(), and is execute()d
    (or enqueue()d as part of a Transaction).

    To accommodate queries that need to feed multiple lines of input
    to a COPY statement, a series of bind() calls may be followed by
    a call to submitLine() to form one line of input. This sequence
    can be repeated as many times as required, and execute() called
    as usual afterwards. (All parameters to a COPY must be bound in
    the Query::Binary format.)

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


/*! Constructs a new empty Query handled by \a ev, which may be 0 to
    disable callbacks. (This form is provided for use by subclasses.)
*/

Query::Query( EventHandler *ev )
    : d( new QueryData )
{
    d->owner = ev;
}


/*! Constructs a Query for \a ev containing the SQL statement \a s.
    If \a ev is 0, the query will run without notifying its owner of
    progress or completion.
*/

Query::Query( const String &s, EventHandler *ev )
    : d( new QueryData )
{
    d->owner = ev;
    setString( s );
}


/*! Constructs a Query for \a ev from the prepared statement \a ps.
    If \a ev is 0, the query will run without notifying its owner of
    progress or completion.
*/

Query::Query( const PreparedStatement &ps, EventHandler *ev )
    : d( new QueryData )
{
    d->owner = ev;
    d->name = ps.name();
    setString( ps.query() );
}


/*! \fn Query::~Query()

    This virtual destructor exists only so that subclasses can define
    their own.
*/


/*! Returns the state of this object, which may be one of the following:

    Inactive: This query has not yet been submitted to the Database.
    Submitted: The query has been submitted to the Database.
    Executing: The query has been sent to the server.
    Completed: The query completed successfully.
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

    This is not communicated to the server, so if this query is part
    of a Transaction, its failure aborts the Transaction.
*/

void Query::allowFailure()
{
    d->canFail = true;
}


/*! Returns true only if allowSlowness() has been called for this query,
    signifying that the query may take a long time, and that the default
    query timeout should not apply.

    This function exists only so that Postgres can avoid timing out when
    it should just wait instead.
*/

bool Query::canBeSlow() const
{
    return d->canBeSlow;
}


/*! If this function is called before execute(), Postgres will not apply
    the default query timeout to this Query. The query continues to be
    processed as it would otherwise.
*/

void Query::allowSlowness()
{
    d->canBeSlow = true;
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


/*! Returns this Query's format, which may be Text (the default) or
    Binary (set for "copy ... with binary" statements). */

Query::Format Query::format() const
{
    return d->format;
}


/*! Binds the integer value \a s to the parameter \a n of this Query. */

void Query::bind( uint n, int s )
{
    if ( d->format == Binary ) {
        String t;
        t.append( (char)( s >> 24 ) );
        t.append( (char)( s >> 16 ) );
        t.append( (char)( s >>  8 ) );
        t.append( (char)( s ) );
        bind( n, t );
    }
    else {
        bind( n, fn( s ) );
    }
}


/*! \overload
    Binds the unsigned 32-bit integer value \a s to the parameter \a n
    of this Query. \a s may not be larger than INT_MAX.
*/

void Query::bind( uint n, uint s )
{
    if ( s > INT_MAX )
        die( Invariant );
    bind( n, (int)s );
}


/*! \overload
    Binds the 64-bit integer value \a s to the parameter \a n of this
    Query.
*/

void Query::bind( uint n, int64 s )
{
    if ( d->format == Binary ) {
        String t;
        t.append( (char)( s >> 56 ) );
        t.append( (char)( s >> 48 ) );
        t.append( (char)( s >> 40 ) );
        t.append( (char)( s >> 32 ) );
        t.append( (char)( s >> 24 ) );
        t.append( (char)( s >> 16 ) );
        t.append( (char)( s >>  8 ) );
        t.append( (char)( s ) );
        bind( n, t );
    }
    else {
        bind( n, fn( s ) );
    }
}


/*! \overload
    Binds the String value \a s to the parameter \a n of this Query in
    the specified format \a f (or the default format for this query if
    \a f is left at the default value of Unknown).
*/

void Query::bind( uint n, const String &s, Format f )
{
    if ( f == Unknown )
        f = d->format;

    d->values->insert( new Value( n, s, f ) );
}


/*! \overload
    Converts \a s to the database's unicode encoding and binds the
    result to the parameter \a n of this Query.
*/

void Query::bind( uint n, const UString &s )
{
    PgUtf8Codec p;
    bind( n, p.fromUnicode( s ) );
}


/*! \overload

    This version binds each number in \a set as parameter \a n.
*/

void Query::bind( uint n, const class IntegerSet & set )
{
    if ( d->format == Text ) {
        String s( "{" );
        s.append( set.csl() );
        s.append( "}" );
        bind( n, s );
    }
    else {
        // XXX: Not implemented yet.
    }

}


/*! \overload

    This version binds each string in \a l as parameter \a n.
*/

void Query::bind( uint n, const StringList & l )
{
    if ( d->format == Text ) {
        String s( "{" );
        s.reserve( l.count() * 16 );
        StringList::Iterator it( l );
        while ( it ) {
            String t( *it );
            if ( t.boring() )
                s.append( t );
            else
                s.append( t.quoted() );
            ++it;
            if ( it )
                s.append( "," );
        }
        s.append( "}" );
        bind( n, s );
    }
    else {
        // XXX: Not implemented yet.
    }
}


/*! \overload
    Binds NULL to the parameter \a n of this Query.
*/

void Query::bindNull( uint n )
{
    d->values->insert( new Value( n ) );
}


/*! Uses the Values bound to this query so far to form one line of input
    to COPY. The bind() functions can then be reused to compose the next
    line of input.
*/

void Query::submitLine()
{
    if ( !d->inputLines )
        d->inputLines = new List< Query::InputLine >;
    d->inputLines->append( d->values );
    d->values = new InputLine;
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


/*! This function sets the contents of this Query to \a s. It is used
    (e.g. by Selector) when arguments need to be bound before the SQL
    statement is completely constructed.

    It has no effect on queries that have already been submitted to
    the database.
*/

void Query::setString( const String &s )
{
    if ( d->state != Inactive )
        return;

    d->query = s;
    if ( s.lower().endsWith( "with binary" ) )
        d->format = Binary;
    if ( s.lower().startsWith( "copy " ) && !d->inputLines )
        d->inputLines = new List< Query::InputLine >;
}


/*! Returns a pointer to the list of Values bound to this Query. */

Query::InputLine *Query::values() const
{
    return d->values;
}


/*! Returns a pointer to the List of InputLines created with bind() and
    submitLine(). Will return 0 if submitLine() has never been called
    for this Query.

    (Should calling this function clear the List?)
*/

List< Query::InputLine > *Query::inputLines() const
{
    return d->inputLines;
}


/*! Sets the owner of this Query to \a ev. */

void Query::setOwner( EventHandler * ev )
{
    d->owner = ev;
}


/*! Returns a pointer to the owner of this Query, as specified during
    construction or with setOwner().
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
    if ( !d->owner ) {
        if ( failed() && d->transaction )
            d->transaction->notify();
        return;
    }

    Scope s( d->owner->log() );
    try {
        d->owner->execute();
    }
    catch ( Exception e ) {
        d->owner = 0; // so we can't get close to a segfault again
        if ( e == Invariant ) {
            setError( "Invariant failed while processing Query::notify()" );

            if ( d->transaction )
                d->transaction->rollback();

            // Analogous to EventLoop::dispatch, we try to close the
            // connection that threw the exception. The problem is
            // that we don't know which one did. So we try to find one
            // whose Log object is an ancestor of this query's owner's
            // Log object.

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


/*! Returns a description of this query and its parameters, if any, that
    is suitable for logging and debugging.
*/

String Query::description()
{
    String s;
    StringList p;

    int i = 0;
    List< Query::Value >::Iterator v( *values() );
    while ( v ) {
        i++;

        String r( "$" );
        r.appendNumber( i );
        r.append( "=" );
        int n = v->length();
        if ( n == -1 ) {
            r.append( "null" );
        }
        else if ( v->format() == Query::Binary ) {
            r.append( "binary: " );
            r.append( String::humanNumber( n ) );
            r.append( "b " );
        }
        else if ( n <= 32 ) {
            r.append( "'" );
            r.append( v->data() );
            r.append( "'" );
        }
        else {
            r.append( "'" );
            r.append( v->data().mid( 0, 12 ) );
            r.append( "'... (" );
            r.append( String::humanNumber( n ) );
            r.append( "b)" );
        }
        p.append( r );
        ++v;
    }

    s.append( "\"" );
    s.append( string() );
    s.append( "\"" );
    if ( i > 0 ) {
        s.append( " (" );
        s.append( p.join(",") );
        s.append( ")" );
    }

    return s;
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
    the Transaction's error message set too.

    This function is intended for use by the Database.
*/

void Query::setError( const String &s )
{
    Scope x( log() );
    d->error = s;
    setState( Failed );
    if ( d->transaction )
        d->transaction->setError( this, s );
    else if ( canFail() )
        ::log( s, Log::Debug );
    else
        ::log( s, Log::Error );
}


/*! Returns the number of rows processed by this Query. This is
    normally the number of rows received from the server in response
    to this Query, but can also be e.g. the number of rows injected.
*/

uint Query::rows() const
{
    return d->totalRows;
}


/*! Informs this Query that the proper value of rows() is \a r. Should
    not be called unless the Query is completely processed.

    Used by Postgres to help queries like "insert into ... select ..."
    return a helpful value of rows().
*/

void Query::setRows( uint r )
{
    d->totalRows = r;
}


/*! Returns true if any rows of data received in response to this Query
    have not yet been read and removed by calling nextRow().
*/

bool Query::hasResults() const
{
    return !d->rows.isEmpty();
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
    return d->rows.shift();
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
*/


/*! Creates a row of data based on the columns \a c, presumed to be
    named \a nameMap. The keys in \a nameMap point to unsigned
    integers; each of which must exist in \a c.
*/

Row::Row( const PatriciaTree<int> * nameMap, Column * c )
    : names( nameMap ), data( c )
{
}


extern "C" {
    uint strlen( const char * );
};


/*! This private helper returns the column named \a f, or a null
    pointer if \a f does not exist.

    If \a warn is true and \a f does not exist or has a type other
    than \a type, then fetch() logs a warning.
*/

const Column * Row::fetch( const char * f, Column::Type type, bool warn ) const
{
    int * x = names->find( f, strlen( f ) * 8 );
    if ( !x ) {
        if ( warn )
            log( "Note: Column " + String( f ).quoted() + " does not exist",
                 Log::Error );
        return 0;
    }

    if ( warn && type != data[*x].type )
        log( "Note: Expected type " + Column::typeName( type ) +
             " for column " + String( f ).quoted() + ", but received " +
             Column::typeName( data[*x].type ), Log::Error );
    return &data[*x];
}


/*! Returns true if the column named \a f is NULL or does not exist,
    and false in all other cases.
*/

bool Row::isNull( const char *f ) const
{
    const Column * c = fetch( f, Column::Null, false );
    if ( !c )
        return true; // XXX the two isNull()s differed

    if ( c->type == Column::Null )
        return true;
    return false;
}


/*! Returns the boolean value of the column named \a f if it exists
    and is NOT NULL, and false otherwise.
*/

bool Row::getBoolean( const char * f ) const
{
    const Column * c = fetch( f, Column::Boolean, true );
    if ( !c )
        return false;
    if ( c->type != Column::Boolean )
        return false;
    return c->b;
}


/*! Returns the integer value of the column named \a f if it exists
    and is NOT NULL, and 0 otherwise.
*/

int Row::getInt( const char * f ) const
{
    const Column * c = fetch( f, Column::Integer, true );
    if ( !c )
        return 0;
    if ( c->type != Column::Integer )
        return 0;
    return c->i;
}


/*! Returns the 64-bit integer (i.e. Postgres bigint) value of the
    column named \a f if it exists and is NOT NULL; 0 otherwise.
*/

int64 Row::getBigint( const char * f ) const
{
    const Column * c = fetch( f, Column::Bigint, true );
    if ( !c )
        return 0;
    if ( c->type != Column::Bigint )
        return 0;
    return c->bi;
}


/*! Returns the string value of the column named \a f i if it exists
    and is NOT NULL, and an empty string otherwise.
*/

String Row::getString( const char * f ) const
{
    const Column * c = fetch( f, Column::Bytes, true );
    if ( !c )
        return "";
    if ( c->type != Column::Bytes )
        return "";
    return c->s;
}


/*! Returns the string value of the column named \a f if it exists
    and is NOT NULL, and an empty string otherwise.
*/

UString Row::getUString( const char * f ) const
{
    UString r;
    const Column * c = fetch( f, Column::Bytes, true );
    if ( !c )
        return r;
    if ( c->type != Column::Bytes )
        return r;
    PgUtf8Codec uc;
    r = uc.toUnicode( c->s );
    return r;
}


/*! Returns true if this Row contains a column named \a f, and false
    otherwise.
*/

bool Row::hasColumn( const char * f ) const
{
    const Column * c = fetch( f, Column::Null, false );
    if ( c )
        return true;
    return false;
}


/*! \class PreparedStatement query.h
    This class represents an SQL prepared statement.

    A PreparedStatement has a name() and an associated query(). Its only
    purpose is to be used to construct Query objects. Each object has a
    unique name.

    A PreparedStatement is never freed during garbage collection.
*/


static int prepareCounter = 0;
List<PreparedStatement> * preparedStatementRoot = 0;


/*! Creates a PreparedStatement containing the SQL statement \a s, and
    generates a unique SQL name for it.
*/

PreparedStatement::PreparedStatement( const String &s )
    : n( fn( prepareCounter++ ) ), q( s )
{
    if ( !preparedStatementRoot ) {
        preparedStatementRoot = new List<PreparedStatement>;
        Allocator::addEternal( preparedStatementRoot, "prepared statements" );
    }
    preparedStatementRoot->append( this );
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

String Column::typeName( Type type )
{
    String n;
    switch( type ) {
    case Unknown:
        n = "unknown";
        break;
    case Boolean:
        n = "boolean";
        break;
    case Bigint:
        n = "bigint";
        break;
    case Integer:
        n = "integer";
        break;
    case Bytes:
        n = "string";
        break;
    case Timestamp:
        n = "timestamptz";
        break;
    case Null:
        n = "null";
        break;
    }
    return n;
}


/*! Returns a pointer to the Log object that's most appropriate to use
    when logging information pertaining to this Query. This is usually
    the Log object belonging to the owner().
*/

class Log * Query::log() const
{
    Log * l = 0;
    if ( d->owner )
        l = d->owner->log();
    if ( !l && d->transaction && d->transaction->owner() )
        l = d->transaction->owner()->log();
    return l;
}


/*! Cancels the query (if possible) and notifies the query's owner.
*/

void Query::cancel()
{
    if ( done() )
        return;

    State s = state();
    setState( Failed );
    if ( s == Executing )
        setError( "Cancelled while executing" );
    else
        setError( "Cancelled" );
    notify();

    // if ( d->canBeSlow && s == Executing ) {
    //     ... send a PostgreSQL cancel...
}
