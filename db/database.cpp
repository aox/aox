/*! \class Database database.h
    Database interface class.
*/

#include "database.h"

#include "arena.h"
#include "scope.h"
#include "string.h"
#include "query.h"
#include "list.h"
#include "log.h"
#include "configuration.h"

#include "postgres.h"


static Arena dbArena;
static Endpoint *srv;
static String *t, *n, *u, *p;
static List< Database > handles;


/*! Creates a new Database object. */

Database::Database()
    : Connection()
{
}


/*! Tries to create the first database handle, and exits if it can't.
    Expects to be called from ::main().
*/

void Database::setup()
{
    Configuration::Text   db(     "db",     "postgres" );
    Configuration::Text   dbHost( "dbhost", "127.0.0.1" );
    Configuration::Scalar dbPort( "dbport", 5432 );
    Configuration::Text   dbUser( "dbuser", "imap" );
    Configuration::Text   dbPass( "dbpass", "" );
    Configuration::Text   dbName( "dbname", "imap" );

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


/*! This function returns a pointer to a Database object that is ready()
    to accept queries. If it can't find an existing handle, it creates a
    new one of the type specified in the configuration file. Returns 0
    if the database type is unsupported.
*/

Database * Database::handle()
{
    Scope x( &dbArena );
    List< Database >::Iterator it;
    Database *db = 0;

    it = handles.first();
    while ( it ) {
        if ( it->ready() ) {
            db = it;
            break;
        }
        it++;
    }

    // XXX: We want to do some sort of rate limiting here.
    if ( !db ) {
        String type = Database::type().lower();

        if ( type == "postgres" )
            db = new Postgres;
    }

    return db;
}


/*! Submits the Query \a q to the database. */

void Database::query( Query * q )
{
    Database * db = handle();
    if ( !db ) {
        q->setState( Query::Failed );
        q->setError( "Couldn't find a database connection." );
        return;
    }
    db->submit( q );
}


/*! \fn bool Database::ready()

    This function must be implemented by subclasses to return true if a
    Database handle is ready to accept a Query via submit().
*/

/*! \fn void Database::submit( Query *q )

    This function must be implemented by subclasses to accept the Query
    \a q for submission to the Database server.
*/

/*! \fn void Database::prepare( PreparedStatement *ps )

    This function must be implemented by subclasses to accept the
    PreparedStatement \a ps for submission to the Database server.
*/


/*! Returns the text of the "db" configuration variable, which tells the
    handle() function which Database subclass to instantiate.
*/

String Database::type() { return *t; }

/*! Returns the configured address of the database server. */

Endpoint Database::server() { return *srv; }

/*! Returns our configured database name. */

String Database::name() { return *n; }

/*! Returns our configured database username. */

String Database::user() { return *u; }

/*! Returns our configured database password. */

String Database::password() { return *p; }


/*! Adds \a d to the pool of active database connections. */

void Database::addHandle( Database * d )
{
    Scope x( &dbArena );
    handles.append(d);
}


/*! Removes \a d from the pool of active database connections. */

void Database::removeHandle( Database * d )
{
    Scope x( &dbArena );
    handles.take( handles.find(d) );
}
