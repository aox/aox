#include "database.h"

#include "arena.h"
#include "scope.h"
#include "list.h"
#include "string.h"
#include "configuration.h"
#include "log.h"

#include "postgres.h"


static Arena dbArena;
static Endpoint *srv;
static String *t, *n, *u, *p;
static List< Database > handles;


/*! \class Database database.h
    This class represents a connection to the database server.

    Callers are expected to acquire a handle(), enqueue() any number of
    Query objects, and execute() them. Most people will use this class
    through the Query or Transaction classes.
*/

/*! \reimp */

Database::Database()
    : Connection()
{
    setType( Connection::DatabaseClient );
}


/*! This setup function expects to be called from ::main().

    It reads and validates the database configuration variables to the
    best of its limited ability (since connection negotiation must be
    left to each subclass), and tries to create the first handle. It
    logs a disaster if it fails.
*/

void Database::setup()
{
    Scope x( &dbArena );

    Configuration::Text db("db", "postgres" );
    Configuration::Text dbUser( "dbuser", "oryx" );
    Configuration::Text dbPass( "dbpass", "" );
    Configuration::Text dbName( "dbname", "imap" );
    Configuration::Text dbHost( "dbhost", "127.0.0.1" );
    Configuration::Scalar dbPort( "dbport", 5432 );

    t = new String( db );
    u = new String( dbUser );
    p = new String( dbPass );
    n = new String( dbName );
    srv = new Endpoint( dbHost, dbPort );

    if ( !srv->valid() ) {
        log( Log::Disaster, "Invalid dbhost address <" + dbHost + "> port <" +
             String::fromNumber( dbPort ) + ">\n" );
        return;
    }

    if ( Database::handle() == 0 ) {
        log( Log::Disaster, "Unsupported database <" + *t + ">\n" );
        return;
    }
}


/*! This static function returns a pointer to a Database object that's
    ready() to accept queries. If it can't find an existing handle, it
    creates a new one of the type specified in the configuration file.
    It returns 0 if the database type is unsupported.

    Note: Although the handle says it is ready(), it may not be usable
    until it has successfully negotiated a connection. This might be a
    bug, but it's not clear where.
*/

Database *Database::handle()
{
    Scope x( &dbArena );

    Database *db = 0;
    List< Database >::Iterator it( handles.first() );
    while ( it ) {
        if ( it->ready() ) {
            db = it;
            break;
        }
        it++;
    }

    // XXX: We should do some sort of rate limiting here.
    if ( !db ) {
        String type = Database::type().lower();

        if ( type == "postgres" )
            db = new Postgres;
    }

    return db;
}


/*! \fn bool Database::ready()

    This function returns true when a database object is ready to accept
    a Query via enqueue(). It will return false after reserve() has been
    has been called, or, for example, if it has too many pending queries
    already.

    Each Database subclass must implement this function.
*/

/*! \fn void Database::reserve()

    This function reserves a database handle for use by the caller. That
    is, it will not be ready() to accept queries until it is release()d.
    For example, one could reserve a handle(), then enqueue() a sequence
    of queries, and execute() them all at once before releasing it. This
    is how Transaction objects work.

    Handles may be reserved only if they are ready(). Reserving a handle
    that has already been reserved does nothing.

    Each Database subclass must implement this function.
*/

/*! \fn void Database::release()

    This function releases a previously reserved database handle, making
    it ready() to accept queries again. A handle should be released only
    by the object that reserved it. Releasing an unreserved handle does
    nothing.

    Each Database subclass must implement this function.
*/

/*! \fn void Database::enqueue( class Query *query )

    This function adds \a query to the database handle's list of queries
    pending submission to the database server. The Query::state() is not
    changed. The query will be sent to the server only when execute() is
    called.

    Enqueuing a query with a Query::transaction() set will automatically
    reserve() the handle until the end of the transaction. An enqueue()d
    query SHOULD be immediately executed unless the handle is reserved.

    Don't enqueue() a Query unless the Database is ready() for one.
*/

/*! \fn void Database::execute()

    This function sends enqueue()d queries to the database server in the
    same order that they were enqueued. The Query::state() is changed to
    either Query::Submitted if the query will only be sent later, or to
    Query::Executing if it was sent immediately.
*/


/*! Returns the text of the "db" configuration variable, which tells the
    handle() function which Database subclass to instantiate.
*/

String Database::type()
{
    return *t;
}


/*! Returns the configured address of the database server. */

Endpoint Database::server()
{
    return *srv;
}


/*! Returns the configured database name. */

String Database::name()
{
    return *n;
}


/*! Returns the configured database username. */

String Database::user()
{
    return *u;
}


/*! Returns the configured database password. */

String Database::password()
{
    return *p;
}


/*! Adds \a d to the pool of active database connections. */

void Database::addHandle( Database * d )
{
    Scope x( &dbArena );
    handles.append( d );
}


/*! Removes \a d from the pool of active database connections. */

void Database::removeHandle( Database * d )
{
    Scope x( &dbArena );
    handles.take( handles.find( d ) );
}
