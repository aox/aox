// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "database.h"

#include "list.h"
#include "string.h"
#include "allocator.h"
#include "configuration.h"
#include "query.h"
#include "log.h"

#include "postgres.h"

// time_t, time
#include <time.h>


List< Query > *Database::queries;
static List< Database > *handles;
static time_t lastCreated;


static void newHandle()
{
    (void)new Postgres;
}


/*! \class Database database.h
    This class represents a connection to the database server.

    The Query and Transaction classes provide the recommended database
    interface. You should never need to use this class directly.

    This is the abstract base class for Postgres (and any other database
    interface classes we implement). It's responsible for validating the
    database configuration, maintaining a pool of database handles, and
    accepting queries into a common queue via submit().
*/

Database::Database()
    : Connection()
{
    setType( Connection::DatabaseClient );
    setState( Database::Connecting );
    lastCreated = time( 0 );
}


/*! This setup function reads and validates the database configuration
    to the best of its limited ability (since connection negotiation
    must be left to subclasses). It logs a disaster if it fails.

    It creates a single database handle at startup for now.

    This function expects to be called from ::main().
*/

void Database::setup()
{
    queries = new List< Query >;
    Allocator::addEternal( queries, "list of queries" );

    handles = new List< Database >;
    Allocator::addEternal( handles, "list of database handles" );

    String db = Configuration::text( Configuration::Db ).lower();
    if ( !( db == "pg" || db == "pgsql" || db == "postgres" ) ) {
        ::log( "Unsupported database type: " + db, Log::Disaster );
        return;
    }

    Endpoint srv( Configuration::DbAddress, Configuration::DbPort );
    if ( !srv.valid() ) {
        ::log( "Invalid server address: " + srv.string(), Log::Disaster );
        return;
    }

    // We create a single handle at startup, and others as needed.
    newHandle();
}


/*! Adds \a q to the queue of submitted queries and sets its state to
    Query::Submitted.
*/

void Database::submit( Query *q )
{
    queries->append( q );
    q->setState( Query::Submitted );

    List< Database >::Iterator it( handles->first() );
    while ( it ) {
        if ( it->state() == Idle ) {
            it->processQueue();
            return;
        }
        ++it;
    }

    // We didn't find an idle handle. Should we create a new one?
    uint max = Configuration::scalar( Configuration::DbMaxHandles );
    int interval = Configuration::scalar( Configuration::DbHandleInterval );
    if ( handles->count() < max &&
         time(0) - lastCreated >= interval )
        newHandle();

    // XXX: We should also find and close handles unused in interval.
}


/*! \fn virtual void Database::processQueue() = 0
    Instructs the Database object to send any queries whose state is
    Query::Submitted to the server.
*/


/*! Sets the state of this Database handle to \a s, which must be one of
    Connecting, Idle, InTransaction, FailedTransaction.
*/

void Database::setState( Database::State s )
{
    st = s;
}


/*! Returns the current state of this Database object. */

Database::State Database::state() const
{
    return st;
}


/*! Adds \a d to the pool of active database connections. */

void Database::addHandle( Database * d )
{
    handles->append( d );
}


/*! Removes \a d from the pool of active database connections. */

void Database::removeHandle( Database * d )
{
    handles->take( handles->find( d ) );
    if ( handles->isEmpty() ) {
        List< Query >::Iterator q( queries->first() );
        while ( q ) {
            q->setError( "No available database handles." );
            q->notify();
            ++q;
        }
    }
}


/*! Returns the configured address of the database server. */

Endpoint Database::server()
{
    return Endpoint( Configuration::DbAddress, Configuration::DbPort );
}


/*! Returns the configured database name. */

String Database::name()
{
    return Configuration::text( Configuration::DbName );
}


/*! Returns the configured database username. */

String Database::user()
{
    return Configuration::text( Configuration::DbUser );
}


/*! Returns the configured database password. */

String Database::password()
{
    return Configuration::text( Configuration::DbPassword );
}
