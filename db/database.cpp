// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "database.h"

#include "allocator.h"
#include "list.h"
#include "string.h"
#include "query.h"
#include "configuration.h"
#include "log.h"

#include "postgres.h"


static Endpoint * srv;
static Database::Interface type;
static String * name;
static String * user;
static String * password;
static List< Database > * handles;


static Database *newHandle( Database::Interface i )
{
    Database *db = 0;

    switch ( i ) {
    case Database::Pg:
        db = new Postgres;
        break;

    case Database::Unknown:
        break;
    }

    return db;
}


/*! \class Database database.h
    This class represents a connection to the database server.

    Callers are expected to acquire a handle(), enqueue() any number of
    Query objects, and execute() them. Most people will use this class
    through the Query or Transaction classes.
*/

Database::Database()
    : Connection()
{
    setType( Connection::DatabaseClient );
}


/*! This setup function expects to be called from ::main().

    It reads and validates the database configuration variables to the
    best of its limited ability (since connection negotiation must be
    left to each subclass). It logs a disaster if it fails.
*/

void Database::setup()
{
    Configuration::Text
        db( "db", "postgres" ),
        dbHost( "db-address",
                Configuration::compiledIn( Configuration::DbAddress ) ),
        dbName( "db-name",
                Configuration::compiledIn( Configuration::DbName ) ),
        dbUser( "db-user",
                Configuration::compiledIn( Configuration::DbUser ) ),
        dbPass( "db-password", "" );
    Configuration::Scalar dbPort( "db-port", 5432 );

    String t = db;
    t = t.lower();
    if ( t == "pg" || t == "pgsql" || t == "postgres" ) {
        ::type = Pg;
    }
    else {
        ::log( "Unsupported database type <" + (String)db + ">",
               Log::Disaster );
        return;
    }


    ::user = new String( dbUser );
    Allocator::addRoot( ::user, "db-user" );
    ::password = new String( dbPass );
    Allocator::addRoot( ::password, "db-password" );
    ::name = new String( dbName );
    Allocator::addRoot( ::name, "db-name" );
    srv = new Endpoint( dbHost, dbPort );
    Allocator::addRoot( srv, "database server" );

    if ( !srv->valid() ) {
        ::log( "Invalid db-address <" + dbHost + "> port " + fn( dbPort ),
               Log::Disaster );
        return;
    }

    if ( srv->protocol() == Endpoint::Unix ) {
        ::log( "Creating four database handles", Log::Info );
        // We can't connect to a Unix socket after a chroot(), so we
        // create four handles right away.
        int i = 0;
        while ( i < 4 ) {
            (void)newHandle( interface() );
            i++;
        }
    }
}


/*! This static function returns a pointer to a Database object that's
    ready() to accept queries. If it can't find an existing handle, it
    creates a new one of the type specified in the configuration file.
    It returns 0 if the database type is unsupported.

    Note: Although the handle says it is ready(), it may not be usable
    until it has successfully negotiated a connection. This might be a
    bug, but it's not clear where.

    There's a BIG BAD BUG when we're using Unix sockets, as this
    function assumes it can create as many sockets as it wants,
    whenever.
*/

Database *Database::handle()
{
    if ( handles ) {
        List< Database >::Iterator it( handles->first() );
        while ( it ) {
            if ( it->ready() )
                return it;
            ++it;
        }
    }

    // XXX: compare the number of handles to some configurable
    // maximum, and return null if we've reached the ceiling.

    return newHandle( interface() );
}


/*! \fn bool Database::ready()

    This function returns true when a database object is ready to accept
    a Query via enqueue(). It may return false when, for example, it has
    too many pending queries already.

    Each Database subclass must implement this function.
*/

/*! \fn void Database::enqueue( class Query *query )

    This function adds \a query to the database handle's list of queries
    pending submission to the database server. The Query::state() is not
    changed. The query will be sent to the server only when execute() is
    called.

    Enqueuing a query with a Query::transaction() set will cause ready()
    to return false, so that non-transaction queries are not enqueued in
    between ones belonging to the transaction.

    Don't enqueue() a Query unless the Database is ready() for one.
*/

/*! \fn void Database::execute()

    This function sends enqueue()d queries to the database server in the
    same order that they were enqueued. The Query::state() is changed to
    either Query::Submitted if the query will only be sent later, or to
    Query::Executing if it was sent immediately.
*/


/*! This static function acquires a database handle, enqueue()s a single
    \a query, and execute()s it. If it cannot find a database handle, it
    calls Query::setError() and returns.
*/

void Database::query( Query *query )
{
    Database *db = handle();

    if ( !db ) {
        query->setError( "No database handle available." );
        return;
    }

    db->enqueue( query );
    db->execute();
}


/*! \overload
    Executes a List \a l of queries on the same database handle().
*/

void Database::query( List< Query > *l )
{
    Database *db = handle();

    List< Query >::Iterator it( l->first() );
    if ( !db ) {
        while ( it ) {
            it->setError( "No database handle available." );
            ++it;
        }
        return;
    }

    while ( it ) {
        db->enqueue( it );
        ++it;
    }
    db->execute();
}


/*! Returns the configured Database::Interface type. This is derived
    from the text of the "db" configuration variable, and tells the
    handle() function which Database subclass to instantiate.
*/

Database::Interface Database::interface()
{
    return ::type;
}


/*! Returns the configured address of the database server. */

Endpoint Database::server()
{
    return *srv;
}


/*! Returns the configured database name. */

String Database::name()
{
    return *::name;
}


/*! Returns the configured database username. */

String Database::user()
{
    return *::user;
}


/*! Returns the configured database password. */

String Database::password()
{
    return *::password;
}


/*! Adds \a d to the pool of active database connections. */

void Database::addHandle( Database * d )
{
    if ( !handles ) {
        handles = new List<Database>;
        Allocator::addRoot( handles, "list of database handles" );
    }
    handles->append( d );
}


/*! Removes \a d from the pool of active database connections. */

void Database::removeHandle( Database * d )
{
    if ( handles )
        handles->take( handles->find( d ) );
}


/*! Returns the name of \a type, mostly for logging purposes. */

String Database::typeName( Type type )
{
    String n;
    switch( type ) {
    case Database::Unknown:
        n = "unknown";
        break;
    case Database::Boolean:
        n = "boolean";
        break;
    case Database::Integer:
        n = "integer";
        break;
    case Database::Bytes:
        n = "string";
        break;
    }
    return n;
}
