// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "database.h"

#include "list.h"
#include "string.h"
#include "allocator.h"
#include "configuration.h"
#include "event.h"
#include "query.h"
#include "file.h"
#include "log.h"

#include "postgres.h"

// time_t, time
#include <time.h>


static uint backendNumber;
List< Query > *Database::queries;
static List< Database > *handles;
static time_t lastExecuted;
static time_t lastCreated;
static Configuration::Text loginAs;


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
    number = ++::backendNumber;
    setType( Connection::DatabaseClient );
    setState( Database::Connecting );
    lastCreated = time( 0 );
}


/*! This setup function reads and validates the database configuration
    to the best of its limited ability (since connection negotiation
    must be left to subclasses). It logs a disaster if it fails.

    It creates \a desired database handles (3 by default) at startup
    and will log in as \a login (Configuration::DbUser by default).

    This function expects to be called from ::main().
*/

void Database::setup( int desired, Configuration::Text login )
{
    if ( !queries ) {
        queries = new List< Query >;
        Allocator::addEternal( queries, "list of queries" );
    }

    if ( !handles ) {
        handles = new List< Database >;
        Allocator::addEternal( handles, "list of database handles" );
    }

    ::loginAs = Configuration::DbUser;
    if ( login == Configuration::DbOwner )
        ::loginAs = login;

    String db = Configuration::text( Configuration::Db ).lower();

    String dbt, ext;
    int n = db.find( '+' );
    if ( n > 0 ) {
        ext = db.mid( n+1 );
        dbt = db.mid( 0, n );
    }
    else {
        dbt = db;
    }

    if ( !( dbt == "pg" || dbt == "pgsql" || dbt == "postgres" ) ||
         !( ext.isEmpty() || ext == "tsearch2" ) )
    {
        ::log( "Unsupported database type: " + db, Log::Disaster );
        return;
    }

    Endpoint srv( Configuration::DbAddress, Configuration::DbPort );
    if ( !srv.valid() ) {
        ::log( "Invalid database server address: " + srv.string(),
               Log::Disaster );
        return;
    }

    if ( desired == 0 ) {
        desired = 3;
        if ( Configuration::toggle( Configuration::Security ) &&
             srv.protocol() == Endpoint::Unix )
            desired = Configuration::scalar( Configuration::DbMaxHandles );
        if ( desired > 4 )
            desired = 4;
    }

    while ( desired ) {
        newHandle();
        desired--;
    }
}


/*! Adds \a q to the queue of submitted queries and sets its state to
    Query::Submitted. The first available handle will process it.
*/

void Database::submit( Query *q )
{
    queries->append( q );
    q->setState( Query::Submitted );
    runQueue();
}


/*! Adds the queries in the list \a q to the queue of submitted queries,
    and sets their state to Query::Submitted. The first available handle
    will process them (but it's not guaranteed that the same handle will
    process them all. Use a Transaction if you depend on ordering).
*/

void Database::submit( List< Query > *q )
{
    List< Query >::Iterator it( q );
    while ( it ) {
        it->setState( Query::Submitted );
        queries->append( it );
        ++it;
    }
    runQueue();
}


/*! This extremely evil function shuts down all Database handles. It's
    used only by lib/installer to reconnect to the database.  Once
    it's done, setup() may be called again with an appropriately
    altered configuration.

    Don't try this at home, kids.
*/

void Database::disconnect()
{
    List< Database >::Iterator it( handles );
    handles = 0;
    while ( it ) {
        it->react( Shutdown );
        ++it;
    }
}


/*! This private function is used to make idle handles process the queue
    of queries, and is called by the two variants of submit().
*/

void Database::runQueue()
{
    int connecting = 0;

    // First, we give each idle handle a Query to process

    Query * first = queries->firstElement();

    List< Database >::Iterator it( handles );
    while ( it ) {
        State st = it->state();

        if ( st == Idle && it->usable() ) {
            it->processQueue();
            if ( queries->isEmpty() )
                return;
        }
        else if ( st == Connecting ) {
            connecting++;
        }

        ++it;
    }

    // If we didn't manage to process even one query, or there aren't
    // any handles now, we can either assume that one of the busy ones
    // will become free and pick up any queued queries, or we can
    // create a new one.

    uint max = Configuration::scalar( Configuration::DbMaxHandles );
    int interval = Configuration::scalar( Configuration::DbHandleInterval );

    if ( ( handles->count() == 0 ||
           time( 0 ) - lastCreated >= interval ||
           ( queries->firstElement() == first && connecting == 0 ) ) &&
         ( server().protocol() != Endpoint::Unix ||
           server().address().startsWith( File::root() ) ) )
    {
        if ( handles->count() >= max ) {
            if ( lastExecuted >= time( 0 ) - interval )
                return;
            handles->first()->react( Close );
        }

        newHandle();
    }
}


/*! \fn virtual void Database::processQueue()
    Instructs the Database object to send any queries whose state is
    Query::Submitted to the server.
*/


/*! Sets the state of this Database handle to \a s, which must be one of
    Connecting, Idle, InTransaction, FailedTransaction.
*/

void Database::setState( State s )
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
    if ( !handles )
        return;

    handles->remove( d );
    if ( !handles->isEmpty() )
        return;

    List< Query >::Iterator q( queries );
    while ( q ) {
        q->setError( "No available database handles." );
        q->notify();
        ++q;
    }

    if ( server().protocol() == Endpoint::Unix &&
         !server().address().startsWith( File::root() ) )
        ::log( "All database handles closed; cannot create any new ones.",
               Log::Disaster );
}


/*! Returns the configured Database type, which may currently be
    postgres or postgres+tsearch2.
*/

String Database::type()
{
    return Configuration::text( Configuration::Db );
}


/*! Returns the configured address of the database server (db-address).
*/

Endpoint Database::server()
{
    return Endpoint( Configuration::DbAddress, Configuration::DbPort );
}


/*! Returns the configured database name (db-name). */

String Database::name()
{
    return Configuration::text( Configuration::DbName );
}


/*! Returns the configured database username (db-user or db-owner). */

String Database::user()
{
    return Configuration::text( ::loginAs );
}


/*! Returns the configured database password (db-password or
    db-owner-password). */

String Database::password()
{
    if ( ::loginAs == Configuration::DbOwner )
        return Configuration::text( Configuration::DbOwnerPassword );
    return Configuration::text( Configuration::DbPassword );
}


/*! Returns the number of database handles currently connected to the
    database.
*/

uint Database::numHandles()
{
    if ( !::handles )
        return 0;
    uint n = 0;
    List<Database>::Iterator it( ::handles );
    while ( it ) {
        if ( it->state() != Connecting )
            n++;
        ++it;
    }
    return n;
}


/*! This static function records the time at which a Database subclass
    issues a query to the database server. It is used to manage the
    creation of new database handles.
*/

void Database::recordExecution()
{
    lastExecuted = time( 0 );
}


/*! Returns true if this Database handle is currently able to process
    queries, and false if it's busy processing queries, is shutting
    down, or for any other reason unwilling to process new queries.
    The default implementation always returns true; subclasses may
    override that behaviour.
*/

bool Database::usable() const
{
    return true;
}


/*! Returns an nonzero positive integer which is unique to this
    database handler.
*/

uint Database::connectionNumber() const
{
    return number;
}


/*! This function returns DbOwner or DbUser, as specified in the call to
    Database::setup().
*/

Configuration::Text Database::loginAs()
{
    return ::loginAs;
}


/*! Checks that the schema revision is appropriate for this server and
    logs a disaster if not. While it's working, the function also
    checks the postgres server version. Instructs \a owner to
    EventHandler::waitFor() the necessary database work.
*/

void Database::checkSchemaRevision( EventHandler * owner )
{
    class SchemaRevisionCheck
        : public EventHandler
    {
    public:
        SchemaRevisionCheck( EventHandler * o ): q( 0 ), owner( o ) {}
        Query * q;
        EventHandler * owner;
        void execute() {
            if ( !q ) {
                q = new Query( "select version() as version, revision from "
                               "mailstore for update", this );
                q->execute();
            }
            if ( !owner )
                return;
            if ( !q->done() )
                return;
            Row * r = q->nextRow();
            if ( q->failed() || !r ) {
                log( "Unable to find server/database version", Log::Disaster );
                owner->execute();
                return;
            }
            String v = r->getString( "version" ).simplified().section( " ", 2 );
            uint revision = r->getInt( "revision" );

            bool ok = true;
            uint version = 10000 * v.section( ".", 1 ).number( &ok ) +
                           100 * v.section( ".", 2 ).number( &ok ) +
                           v.section( ".", 3 ).number( &ok );
            if ( !ok || version < 70402 ) {
                ::log( "Archiveopteryx requires PostgreSQL 7.4.2 "
                       "or higher (found only '" + v + "'", Log::Disaster );
            }
            if ( revision != Database::currentRevision() ) {
                // copied code from schema.cpp. urk.
                String s( "The existing schema (revision " );
                s.append( fn( revision ) );
                s.append( ") is " );
                if ( revision < Database::currentRevision() )
                    s.append( "older" );
                else
                    s.append( "newer" );
                s.append( " than this server (version " );
                s.append( Configuration::compiledIn( Configuration::Version ) );
                s.append( ") expected (revision " );
                s.append( fn( Database::currentRevision() ) );
                s.append( "). Please " );
                if ( revision < Database::currentRevision() )
                    s.append( "run 'aox upgrade schema'" );
                else
                    s.append( "upgrade" );
                s.append( " or contact support." );
                log( s, Log::Disaster );
            }
            owner->execute();
        }
    };
        
    SchemaRevisionCheck * s = new SchemaRevisionCheck( owner );
    s->execute();
    owner->waitFor( s->q );
}


/*! This function checks that the server doesn't have privileged access
    to the database. It notifies \a owner when the check is complete. A
    disaster is logged if the server is connected to the database as an
    unduly privileged user.

    The function expects to be called from ::main() after
    Database::checkSchemaRevision().
*/

void Database::checkAccess( EventHandler * owner )
{
    class AccessChecker
        : public EventHandler
    {
    public:
        Log * l;
        Query * q;
        Query * result;

        AccessChecker( EventHandler * owner )
            : l( new Log( Log::Database ) ), q( 0 ), result( 0 )
        {
            result = new Query( owner );
        }

        void execute()
        {
            if ( !q ) {
                q = new Query( "select not exists (select * from "
                               "information_schema.table_privileges where "
                               "privilege_type='DELETE' and table_name="
                               "'messages' and grantee=$1) and not exists "
                               "(select u.usename from pg_catalog.pg_class c "
                               "left join pg_catalog.pg_user u on "
                               "(u.usesysid=c.relowner) where c.relname="
                               "'messages' and u.usename=$1) as allowed",
                               this );
                q->bind( 1, Configuration::text( Configuration::DbUser ) );
                q->execute();
            }

            if ( !q->done() )
                return;

            Row * r = q->nextRow();
            if ( q->failed() || !r ||
                 r->getBoolean( "allowed" ) == false )
            {
                String s( "Refusing to start because we have too many "
                          "privileges on the messages table in secure "
                          "mode." );
                result->setError( s );
                l->log( s, Log::Disaster );
                if ( q->failed() ) {
                    l->log( "Query: " + q->description(), Log::Disaster );
                    l->log( "Error: " + q->error(), Log::Disaster );
                }
            }
            else {
                result->setState( Query::Completed );
            }

            result->notify();
        }
    };

    AccessChecker * a = new AccessChecker( owner );
    a->execute();
    owner->waitFor( a->result );
}


/*! This static function returns the schema revision current at the time
     this server was compiled.
*/

uint Database::currentRevision()
{
    return 36;
}
