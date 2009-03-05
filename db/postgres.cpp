// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "postgres.h"

#include "dict.h"
#include "list.h"
#include "estring.h"
#include "buffer.h"
#include "dbsignal.h"
#include "allocator.h"
#include "configuration.h"
#include "transaction.h"
#include "estringlist.h"
#include "pgmessage.h"
#include "eventloop.h"
#include "graph.h"
#include "query.h"
#include "event.h"
#include "scope.h"
#include "md5.h"
#include "log.h"

// crypt(), setreuid(), getpwnam()
#define _XOPEN_SOURCE 600
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>


static bool hasMessage( Buffer * );
static uint serverVersion;
static Postgres * listener = 0;


class PgData
    : public Garbage
{
public:
    PgData()
        : active( false ), startup( false ), authenticated( false ),
          unknownMessage( false ), identBreakageSeen( false ),
          setSessionAuthorisation( false ),
          sendingCopy( false ), error( false ),
          mustSendListen( false ), keydata( 0 ),
          description( 0 ), transaction( 0 ),
          needNotify( 0 )
    {}

    bool active;
    bool startup;
    bool authenticated;
    bool unknownMessage;
    bool identBreakageSeen;
    bool setSessionAuthorisation;
    bool sendingCopy;
    bool error;
    bool mustSendListen;
    EStringList listening;

    PgKeyData *keydata;
    PgRowDescription *description;
    Dict<Postgres> prepared;
    EStringList preparesPending;

    List< Query > queries;
    Transaction *transaction;
    Query * needNotify;

    EString user;
};


/*! \class Postgres postgres.h
    Implements the PostgreSQL 3.0 Frontend-Backend protocol.

    This is our interface to PostgreSQL. As a subclass of Database, it
    accepts Query objects, sends queries to the database, and notifies
    callers about any resulting data. As a descendant of Connection, it
    is responsible for all network communications with the server.

    The network protocol is documented at <doc/src/sgml/protocol.sgml>
    and <http://www.postgresql.org/docs/current/static/protocol.html>.
    The version implemented here is used by PostgreSQL 7.4 and later.

    At the time of writing, there do not seem to be any other suitable
    PostgreSQL client libraries available. For example, libpqxx doesn't
    support asynchronous operation or prepared statements. Its interface
    would be difficult to wrap in a database-agnostic manner, and it
    depends on the untested libpq. The others aren't much better.
*/

/*! Creates a Postgres object, initiates a TCP connection to the server,
    registers with the main loop, and adds this Database to the list of
    available handles.
*/

Postgres::Postgres()
    : Database(), d( new PgData )
{
    d->user = Database::user();
    struct passwd * p = getpwnam( d->user.cstr() );
    if ( p && getuid() != p->pw_uid ) {
        // Try to cooperate with ident authentication.
        uid_t e = geteuid();
        setreuid( 0, p->pw_uid );
        connect( address(), port() );
        setreuid( 0, e );
    }
    else {
        connect( address(), port() );
    }

    log( "Connecting to PostgreSQL server at " +
         address() + ":" + fn( port() ) + " "
         "(backend " + fn( connectionNumber() ) + ", fd " + fn( fd() ) +
         ", user " + d->user + ")", Log::Debug );

    if ( Connection::state() != Invalid ) {
        setTimeoutAfter( 10 );
        EventLoop::global()->addConnection( this );
    }
    addHandle( this );
}


Postgres::~Postgres()
{
    EventLoop::global()->removeConnection( this );
}


void Postgres::processQueue()
{
    Query *q;
    int n = 0;

    if ( d->sendingCopy )
        return;

    List< Query > *l = Database::queries;
    if ( d->transaction )
        l = d->transaction->enqueuedQueries();

    while ( ( q = l->firstElement() ) != 0 ) {
        if ( q->state() != Query::Submitted )
            break;

        l->shift();
        q->setState( Query::Executing );

        Transaction * t = q->transaction();
        if ( t && t != d->transaction ) {
            d->transaction = t;
            t->setState( Transaction::Executing );
            t->setDatabase( this );
            l = t->enqueuedQueries();
        }

        if ( !d->error ) {
            d->queries.append( q );
            processQuery( q );
            n++;

            if ( q->inputLines() ) {
                d->sendingCopy = true;
                break;
            }

            if ( !d->transaction )
                break;
        }
        else {
            q->setError( "Database handle no longer usable." );
            q->notify();
        }
    }

    if ( n > 0 ) {
        extendTimeout( Configuration::scalar( Configuration::DbHandleInterval ) );
        write();
    }
    else {
        reactToIdleness();
    }
}


/*! Sends whatever messages are required to make the backend process the
    query \a q.
*/

void Postgres::processQuery( Query * q )
{
    Scope x( q->log() );
    EString s( "Sent " );
    if ( q->name() == "" ||
         !d->prepared.contains( q->name() ) )
    {
        PgParse a( queryString( q ), q->name() );
        a.enqueue( writeBuffer() );

        if ( q->name() != "" ) {
            d->prepared.insert( q->name(), this );
            d->preparesPending.append( q->name() );
        }

        s.append( "parse/" );
    }

    PgBind b( q->name() );
    b.bind( q->values() );
    b.enqueue( writeBuffer() );

    PgDescribe c;
    c.enqueue( writeBuffer() );

    PgExecute ex;
    ex.enqueue( writeBuffer() );

    PgSync e;
    e.enqueue( writeBuffer() );

    s.append( "execute for " );
    s.append( q->description() );
    s.append( " on backend " );
    s.appendNumber( connectionNumber() );
    ::log( s, Log::Debug );
    recordExecution();
}


void Postgres::react( Event e )
{
    switch ( e ) {
    case Connect:
        {
            PgStartup msg;
            msg.setOption( "user", d->user );
            msg.setOption( "database", name() );
            msg.setOption( "search_path",
                           Configuration::text( Configuration::DbSchema ) );
            msg.enqueue( writeBuffer() );

            d->active = true;
            d->startup = true;
        }
        break;

    case Read:
        while ( d->active && hasMessage( readBuffer() ) ) {
            /* We call a function to process every message we receive.
               This function is expected to parse and remove a message
               from the readBuffer, throwing an exception for malformed
               messages, and setting d->unknownMessage for messages that
               it can't or won't handle. */

            char msg = (*readBuffer())[0];
            try {
                if ( d->startup ) {
                    if ( !d->authenticated )
                        authentication( msg );
                    else
                        backendStartup( msg );
                }
                else {
                    process( msg );
                }

                if ( d->unknownMessage )
                    unknown( msg );
            }
            catch ( PgServerMessage::Error e ) {
                error( "Malformed " + EString( &msg, 1 ).quoted() +
                       " message received." );
            }
        }
        if ( d->needNotify )
            d->needNotify->notify();
        d->needNotify = 0;

        if ( d->authenticated && Connection::state() == Connected && !::listener ) {
            ::listener = this;
            sendListen();
        }

        if ( usable() ) {
            processQueue();
            if ( d->queries.isEmpty() ) {
                uint interval =
                    Configuration::scalar( Configuration::DbHandleInterval );
                if ( ::listener == this )
                    interval = interval * 2;
                setTimeoutAfter( interval );
            }
        }

        break;

    case Error:
        error( "Couldn't connect to PostgreSQL." );
        break;

    case Close:
        if ( d->active )
            error( "Connection terminated by the server." );
        if ( ::listener == this )
            ::listener = 0;
        break;

    case Timeout:
        if ( !d->active || d->startup ) {
            error( "Timeout negotiating connection to PostgreSQL." );
        }
        else if ( d->transaction || !d->queries.isEmpty() ) {
            Query * q = d->queries.firstElement();
            Scope x;
            if ( q )
                x.setLog( q->log() );
            if ( q && q->canBeSlow() ) {
                extendTimeout( 10 );
            }
            else {
                if ( d->transaction ) {
                    ::log( "Transaction timeout on backend " +
                           fn( connectionNumber() ), Log::Error );
                    Transaction * t = d->transaction;
                    while ( t ) {
                        t->setError( 0, "Transaction timeout" );
                        t->rollback();
                        t = t->parent();
                    }
                }
                else {
                    error( "Request timeout on backend " +
                           fn( connectionNumber() ) );
                }
            }
        }
        else if ( server().protocol() != Endpoint::Unix &&
                  ::listener != this &&
                  handlesNeeded() > numHandles() ) {
            log( "Closing idle database handle (" +
                 fn( numHandles()-1 ) + " remaining)" );
            shutdown();
        }
        else {
            uint interval =
                Configuration::scalar( Configuration::DbHandleTimeout );
            extendTimeout( interval );
        }
        break;

    case Shutdown:
        shutdown();
        break;
    }
}


/*! This function handles the authentication phase of the protocol. It
    expects and responds to an authentication request, and waits for a
    positive response before entering the backend startup phase. It is
    called by react with the \a type of the message to process.
*/

void Postgres::authentication( char type )
{
    switch ( type ) {
    case 'R':
        {
            PgAuthRequest r( readBuffer() );

            switch ( r.type() ) {
            case PgAuthRequest::Success:
                d->authenticated = true;
                break;

            case PgAuthRequest::Password:
            case PgAuthRequest::Crypt:
            case PgAuthRequest::MD5:
                {
                    EString pass = password();

                    if ( d->setSessionAuthorisation ) {
                        error( "Cannot supply credentials during proxy "
                               "authentication" );
                        return;
                    }

                    if ( r.type() == PgAuthRequest::Crypt )
                        pass = ::crypt( pass.cstr(), r.salt().cstr() );
                    else if ( r.type() == PgAuthRequest::MD5 )
                        pass = "md5" + MD5::hash(
                                           MD5::hash(
                                               pass + d->user
                                           ).hex() + r.salt()
                                       ).hex();

                    PgPasswordMessage p( pass );
                    p.enqueue( writeBuffer() );
                }
                break;

            default:
                error( "Unsupported PgAuthRequest." );
                break;
            }
        }
        break;

    default:
        d->unknownMessage = true;
        break;
    }
}


/*! This function negotiates the backend startup phase of the protocol
    (storing any messages the server sends us), concluding the startup
    process when the server indicates that it is ready for queries. It
    is called by react() with the \a type of the message to process.
*/

void Postgres::backendStartup( char type )
{
    switch ( type ) {
    case 'Z':
        setTimeout( 0 );
        d->startup = false;

        // This successfully concludes connection startup. We'll leave
        // this message unparsed, so that process() can handle it like
        // any other PgReady.

        if ( d->setSessionAuthorisation ) {
            Query * q =
                new Query( "SET SESSION AUTHORIZATION " +
                           Database::user(), 0 );
            d->queries.append( q );
            processQuery( q );
        }

        break;

    case 'K':
        d->keydata = new PgKeyData( readBuffer() );
        log( "Postgres backend " + fn( connectionNumber() ) +
             " has pid " + fn( d->keydata->pid() ), Log::Debug );
        break;

    default:
        d->unknownMessage = true;
        break;
    }
}


/*! This function handles interaction with the server once the startup
    phase is complete. It is called by react() with the \a type of the
    message to process.
*/

void Postgres::process( char type )
{
    Query * q = d->queries.firstElement();
    Scope x;
    if ( q && q->log() )
        x.setLog( q->log() );

    extendTimeout( 5 );

    switch ( type ) {
    case '1':
        {
            PgParseComplete msg( readBuffer() );
            if ( q && q->name() != "" )
                d->preparesPending.shift();
        }
        break;

    case '2':
        {
            PgBindComplete msg( readBuffer() );
        }
        break;

    case 'n':
        {
            PgNoData msg( readBuffer() );
        }
        break;

    case 't':
        (void)new PgParameterDescription( readBuffer() );
        break;

    case 'G':
        {
            PgCopyInResponse msg( readBuffer() );
            if ( q && q->inputLines() ) {
                PgCopyData cd( q );
                PgCopyDone e;

                cd.enqueue( writeBuffer() );
                e.enqueue( writeBuffer() );
            }
            else {
                PgCopyFail f;
                f.enqueue( writeBuffer() );
            }

            PgSync s;
            s.enqueue( writeBuffer() );
            d->sendingCopy = false;
        }
        break;

    case 'T':
        d->description = new PgRowDescription( readBuffer() );
        break;

    case 'D':
        {
            if ( !q || !d->description ) {
                error( "Unexpected data row" );
                return;
            }

            PgDataRow msg( readBuffer(), d->description );
            q->addRow( msg.row() );
            if ( d->needNotify && d->needNotify != q )
                d->needNotify->notify();
            d->needNotify = q;
        }
        break;

    case 'I':
    case 'C':
        {
            PgCommandComplete * cc = 0;
            if ( type == 'C' )
                cc = new PgCommandComplete( readBuffer() );
            else
                PgEmptyQueryResponse msg( readBuffer() );

            if ( q ) {
                EString s;
                s.append( "Dequeueing query " );
                s.append( q->description() );
                s.append( " on backend " );
                s.appendNumber( connectionNumber() );
                EString command;
                if ( cc )
                    command = cc->tag().section( " ", 1 );
                if ( cc && !q->rows() ) {
                    uint an = 2;
                    if ( command == "INSERT" )
                        an = 3;
                    q->setRows( cc->tag().section( " ", an ).number( 0 ) );
                }
                if ( q->rows() ||
                     command == "SELECT" || command == "FETCH" ||
                     command == "INSERT" || command == "UPDATE" ) {
                    s.append( " (with " );
                    s.appendNumber( q->rows() );
                    s.append( " rows)" );
                }
                ::log( s, Log::Info );
                if ( !q->done() ) {
                    q->setState( Query::Completed );
                    countQueries( q );
                }
                d->queries.shift();
                q->notify();
                d->needNotify = 0;
            }
        }
        break;

    case 'Z':
        {
            PgReady msg( readBuffer() );

            if ( state() == InTransaction ||
                 state() == FailedTransaction )
            {
                if ( msg.state() == FailedTransaction ) {
                    d->transaction->setState( Transaction::Failed );
                }
                else if ( msg.state() == Idle ) {
                    if ( !d->transaction->failed() )
                        d->transaction->setState( Transaction::Completed );
                    d->transaction->notify();
                    d->transaction = d->transaction->parent();
                }
                else if ( state() == FailedTransaction ) {
                    if ( msg.state() == InTransaction || msg.state() == Idle )
                        d->transaction->clearError();
                }
            }

            setState( msg.state() );

        }
        break;

    case 'A':
        {
            PgNotificationResponse msg( readBuffer() );
            EString s;
            if ( !msg.source().isEmpty() )
                s = " (" + msg.source() + ")";
            log( "Received notify " + msg.name().quoted() +
                 " from server pid " + fn( msg.pid() ) + s, Log::Debug );
            DatabaseSignal::notifyAll( msg.name() );
        }
        break;

    default:
        d->unknownMessage = true;
        break;
    }
}


/*! This function handles unknown or unwanted messages that some other
    function declined to process (by setting d->unknownMessage). It is
    called by react() with the \a type of the unknown message.
*/

void Postgres::unknown( char type )
{
    switch ( type ) {
    case 'S':
        {
            d->unknownMessage = false;
            PgParameterStatus msg( readBuffer() );

            EString n = msg.name();
            EString v = msg.value();
            EString e;
            bool known = true;
            if ( n == "client_encoding" ) {
                if ( v != "UTF8" && v != "SQL_ASCII" )
                    e = "Unexpected client encoding: ";
            }
            else if ( n == "DateStyle" ) {
                // we want ISO on the list somewhere
                if ( !v.containsWord( "ISO" ) )
                    e = "DateStyle apparently does not support ISO: ";
            }
            else if ( n == "integer_datetimes" ) {
                // PG documentation says:
                //     "Use 64-bit integer storage for datetimes and
                //     intervals, rather than the default floating-point
                //     storage. This reduces the range of representable
                //     values but guarantees microsecond precision across
                //     the full range (see Section 8.5 for more
                //     information)."
                // We don't care about that. Email uses only seconds,
                // and only a fairly limited time range. Both on and
                // off are okay.
            }
            else if ( n == "is_superuser" ) {
                if ( v.simplified().lower() != "off" )
                    e = "Connected as superuser: ";
            }
            else if ( n == "server_encoding" ) {
                if ( v != "UTF8" && v != "SQL_ASCII" )
                    e = "Unexpected server encoding: ";
            }
            else if ( n == "server_version" ) {
                bool ok = true;
                serverVersion = 10000 * v.section( ".", 1 ).number( &ok ) +
                                100 * v.section( ".", 2 ).number( &ok ) +
                                v.section( ".", 3 ).number( &ok );
                if ( !ok || version() < 80100 )
                    e = "Archiveopteryx requires PostgreSQL 8.1 or higher: ";
            }
            else if ( n == "session_authorization" ) {
                // we could test that v is d->user, but I don't think
                // we care. besides it might sound an alarm about our
                // ident workarounds.
            }
            else if ( n == "standard_conforming_strings" ) {
                // hm... ?
            }
            else if ( n == "TimeZone" ) {
                // we don't care.
            }
            else {
                known = false;
            }
            if ( known && e.isEmpty() ) {
                // we're entirely silent about this. all is well.
            }
            else {
                EString s( "PostgreSQL server: " );
                if ( e.isEmpty() )
                    s.append( "SET " );
                else
                    s.append( e );
                s.append( n );
                s.append( "=" );
                s.append( v.quoted() );
                if ( e.isEmpty() )
                    ::log( s, Log::Debug );
                else
                    ::log( s );
            }
        }
        break;

    case 'N':
    case 'E':
        d->unknownMessage = false;
        serverMessage();
        break;

    default:
        {
            EString err = "Unexpected message (";

            if ( type > 32 && type < 127 )
                err.append( type );
            else
                err.append( "%" + fn( (int)type, 16 ) );

            err.append( ") received" );
            if ( d->startup ) {
                if ( !d->authenticated )
                    err.append( " during authentication" );
                else
                    err.append( " during backend startup" );
            }
            err.append( "." );
            error( err );
        }
        break;
    }
}


/*! This function handles errors and other messages from the server. */

void Postgres::serverMessage()
{
    Scope x;
    EString s;
    PgMessage msg( readBuffer() );
    Query *q = d->queries.firstElement();
    EString m( msg.message() );
    EString code = msg.code();
    Endpoint server( peer() );

    if ( code == "57P03" ) {
        log( "Retrying connection after delay because PostgreSQL "
             "is still starting up.", Log::Info );
        close();
        sleep( 1 );
        connect( server );
    }
    else if ( code == "57P01" || code == "57P02" ) {
        if ( code == "57P01" )
            log( "PostgreSQL is shutting down; closing connection.", Log::Info );
        else
            log( "PostgreSQL reports a crash; closing connection.", Log::Info );
        removeHandle( this );
        if ( ::listener == this ) {
            ::listener = 0;
            log( "Notify listener went away." );
        }
        close();
        if ( d->transaction ) {
            error( "PostgreSQL server shut down" );
        }
        else {
            List< Query >::Iterator q( d->queries );
            while ( q ) {
                submit( q );
                ++q;
            }
        }
    }
    else if ( code == "28000" && m.lower().containsWord( "ident" ) ) {
        int b = m.find( '"' );
        int e = m.find( '"', b+1 );
        EString user( m.mid( b+1, e-b-1 ) );

        struct passwd * u = getpwnam( d->user.cstr() );

        struct passwd * p = 0;
        const char * pg
            = Configuration::compiledIn( Configuration::PgUser );

        if ( pg )
            p = getpwnam( pg );
        if ( !p )
            p = getpwnam( "postgres" );
        if ( !p )
            p = getpwnam( "pgsql" );

        if ( !d->identBreakageSeen && loginAs() == DbOwner &&
             u == 0 && p != 0 )
        {
            d->identBreakageSeen = true;
            d->setSessionAuthorisation = true;
            log( "Attempting to authenticate as superuser to use "
                 "SET SESSION AUTHORIZATION", Log::Info );
            d->user = EString( p->pw_name );
            uid_t e = geteuid();
            setreuid( 0, p->pw_uid );
            close();
            connect( server );
            setreuid( 0, e );
        }
        else if ( s == Configuration::text(Configuration::JailUser) &&
                  Configuration::toggle( Configuration::Security ) &&
                  self().protocol() != Endpoint::Unix )
        {
            // If we connected via IPv4 or IPv6, early enough that
            // postgres had a chance to reject us, we'll try again.
            d->identBreakageSeen = true;
            log( "PostgreSQL demanded IDENT, which did not match "
                 "during startup. Retrying.", Log::Info );
            close();
            connect( server );
        }
        else {
            log( "PostgreSQL refuses authentication because this "
                 "process is not running as user " + user.quoted() +
                 ". See http://aox.org/faq/mailstore#ident",
                 Log::Disaster );
        }
    }
    else if ( code == "28000" ) {
        log( "Cannot authenticate as PostgreSQL user " + d->user.quoted() +
             ". Server message: " + msg.message(), Log::Disaster );
    }
    else if ( code.startsWith( "53" ) ) {
        uint m = Configuration::scalar( Configuration::DbMaxHandles );
        if ( code == "53000" )
            log( "PostgreSQL server reports too many client connections. "
                 "Our connection count is " + fn( numHandles() ) + ", "
                 "configured maximum is " + fn( m ) + ".",
                 Log::Error );
        else
            log( "PostgreSQL server has a resource problem (" + code + "): " +
                 msg.message(),
                 Log::Significant );
        if ( m > 2 ) {
            log( "Setting db-max-handles to 2 (was " + fn( m ) + ")" );
            Configuration::add( "db-max-handles = 2" );
        }

    }
    else if ( msg.type() == PgMessage::Notification ) {
        s.append( "PostgreSQL server: " );
        if ( q ) {
            s.append( "Query " + q->description() + ": " );
            x.setLog( q->log() );
        }
        s.append( m );
        if ( !code.startsWith( "00" ) )
            s.append( " (warning)" );
        ::log( s, Log::Debug );
    }
    else if ( q && !code.startsWith( "00" ) ) {
        s.append( "PostgreSQL server: " );
        s.append( "Query " + q->description() + " failed: " );
        x.setLog( q->log() );
        s.append( m );
        if ( !msg.detail().isEmpty() )
            s.append( " (" + msg.detail() + ")" );
        s.append( " (" + code + ")" );

        // If we sent a Parse message for a named prepared statement
        // while processing this query, but don't already know that
        // it succeeded, we'll assume that statement name does not
        // exist for future use.
        EString * pp = d->preparesPending.first();
        if ( q->name() != "" && pp && *pp == q->name() ) {
            d->prepared.remove( q->name() );
            d->preparesPending.shift();
        }
        if ( q->inputLines() )
            d->sendingCopy = false;
        d->queries.shift();
        q->setError( mapped( m ) );
        q->notify();
    }
    else {
        ::log( "PostgreSQL server message could not be interpreted."
               " Message: " + msg.message() +
               " SQL state code: " + code +
               " Severity: " + msg.severity().lower(),
               Log::Error );
    }

    if ( code.startsWith( "08" ) ) // connection exception
        error( "PostgreSQL server error: " + s );
}


// these errors are based on a selection of the results from
// select indexname from pg_indexes where tablename in
//  (select tablename from pg_tables where tableowner='aoxsuper')

static const struct {
    const char * constraint;
    const char * human;
} errormap[] = {
    // some index names
    {"addresses_nld_key",
     "Operation would create two identical addresses" },
    {"u_l",
     "Operation wold create two users with identical login names"},
    // some constraints from our postgresql schema
    {"aliases_address_fkey", // contype f
     "Operation would create two aliases with the same address"},
    {"aliases_address_key", // contype u
     "Operation would create two aliases with the same address"},
    {"annotation_names_name_key", // contype u
     "Operation would create two annotation_names rows with the same_name"},
    {"annotations_mailbox_key", // contype u
     "Operation would create a duplicate annotations row"},
    {"annotations_mailbox_key1", // contype u
     "Operation would create a duplicate annotations row"},
    // XXX where does the annotations unique condition end up?
    {"deliveries_message_key", // contype u
     "Operation would store the same message for delivery twice"},
    {"field_names_name_key", // contype u
     "Operation would create two header field names with the same name"},
    {"fn_uname",
     "Operation would store two identical flag names separately"},
    {"group_members_groupname_fkey", // contype f
     "Operation would create group_members row with invalid groupname"},
    {"group_members_member_fkey", // contype f
     "Operation would create group_members row with invalid member"},
    {"group_members_pkey", // contype p
     "Operation would create duplicate group_members row"},
    // XXX shouldb't groups.name be unique? and different from all users.name?
    {"mailboxes_name_key", // contype u
     "Operation would create two mailboxes with the same name"},
    {"mailboxes_owner_fkey", // contype f
     "Operation would create a mailbox without an owner"},
    {"messages_id_key", // contype u
     "Opeation would create two messages objects with the same ID"},
    {"namespaces_name_key", // contype u
     "Operation would create two user namespaces with the same name"},
    {"permissions_mailbox_fkey", // contype f
     "Operation would create a permissions row without a mailbox"},
    {"permissions_pkey", // contype p
     "Operation would create a duplicate permissions row"},
    {"scripts_owner_key", // contype u
     "Operation would store two scripts with the same owner and name"},
    // XXX shouldn't users.alias be unique?
    {"users_alias_fkey", // contype f
     "users_alias"},
    {"users_parentspace_fkey", // contype f
     "Operation would create a users row without a namespace"},
    {0,0}
};



/*! Looks for constraint names in \a s and returns an error message
    corresponding to the relevant constraint. Returns \a s if it finds
    none.
*/

EString Postgres::mapped( const EString & s ) const
{
    if ( !s.contains( "_" ) )
        return "PostgreSQL Server: " + s;

    EString h;
    uint maps = 0;
    EString w;
    uint i = 0;
    while ( maps < 2 && i <= s.length() ) {
        char c = s[i];
        if ( ( c >= 'a' && c <= 'z' ) ||
             ( c >= 'A' && c <= 'Z' ) ||
             ( c >= '0' && c <= '9' ) ||
             ( c == '_' ) ) {
            w.append( c );
        }
        else if ( !w.isEmpty() ) {
            uint j = 0;
            while ( errormap[j].constraint && w != errormap[j].constraint )
                j++;
            if ( errormap[j].constraint ) {
                maps++;
                h = errormap[j].human;
                h.append( " (" );
                h.append( w );
                h.append( ")" );
            }
            w.truncate();
        }
        i++;
    }
    if ( maps != 1 )
        return "PostgreSQL Server: " + s;

    return h;
}



/*! Handles all protocol/socket errors by logging the error message \a s
    and closing the connection after emptying the write buffer and
    notifying any pending queries of the failure.

*/

void Postgres::error( const EString &s )
{
    Scope x( log() );
    ::log( s, Log::Error );

    d->error = true;
    d->active = false;
    setState( Broken );

    List< Query >::Iterator q( d->queries );
    while ( q ) {
        q->setError( s );
        q->notify();
        ++q;
    }

    removeHandle( this );

    writeBuffer()->remove( writeBuffer()->size() );
    Connection::setState( Closing );
}


/*! Sends a termination message and takes this database handle out of
    circulation gracefully.
*/

void Postgres::shutdown()
{
    PgTerminate msg;
    msg.enqueue( writeBuffer() );

    while ( d->transaction ) {
        d->transaction->setError( 0, "Database connection shutdown" );
        d->transaction->notify();
        d->transaction = d->transaction->parent();
    }
    List< Query >::Iterator q( d->queries );
    while ( q ) {
        if ( !q->done() ) {
            q->setError( "Database connection shutdown" );
            q->notify();
        }
        ++q;
    }

    removeHandle( this );
    d->active = false;
}


static bool hasMessage( Buffer *b )
{
    if ( b->size() < 5 ||
         b->size() < 1+( (uint)((*b)[1]<<24)|((*b)[2]<<16)|
                               ((*b)[3]<<8)|((*b)[4]) ) )
        return false;
    return true;
}


/*! Returns true if this handle is willing to process new queries: i.e.
    if it has an active and error-free connection to the server, and no
    outstanding queries; and false otherwise.
*/

bool Postgres::usable() const
{
    return ( d->active && !d->startup &&
             !( state() == Connecting || state() == Broken ) &&
             d->queries.isEmpty() );
}


static GraphableCounter * goodQueries = 0;
static GraphableCounter * badQueries = 0;


/*! Updates the statistics when \a q is done. */

void Postgres::countQueries( class Query * q )
{
    if ( !goodQueries ) {
        goodQueries = new GraphableCounter( "queries-executed" ); // bad name?
        badQueries = new GraphableCounter( "queries-failed" ); // bad name?
    }

    if ( !q->failed() )
        goodQueries->tick();
    else if ( !q->canFail() )
        badQueries->tick();
    ; // a query which fails but canFail is not counted anywhere.

    // later also use GraphableDataSet to keep track of query
    // execution times, but not right now.
}


/*! Returns the Postgres server's declared version number as an
    integer. 8.1.0 is returned as 80100, 8.3.2 as 80302.

    The version number is learned immediately after connecting.
    version() returns 0 until the first Postgres instance learns the
    server version.
*/

uint Postgres::version()
{
    return ::serverVersion;
}


/*! Makes sure Postgres sends as many LISTEN commands as necessary,
    see DatabaseSignal and
    http://www.postgresql.org/docs/8.1/static/sql-listen.html

*/

void Postgres::sendListen()
{
    if ( !::listener )
        return;
    ::listener->d->mustSendListen = true;
    if ( ::listener->state() != Idle || ::listener->d->transaction )
        return;
    ::listener->d->mustSendListen = false;
    EStringList::Iterator s( DatabaseSignal::names() );
    while ( s ) {
        EString name = *s;
        ++s;
        if ( !::listener->d->listening.contains( name ) ) {
            ::listener->d->listening.append( name );
            if ( !name.boring() )
                name = name.quoted();
            Query * q = new Query( "listen " + name, 0 );
            ::listener->d->queries.append( q );
            ::listener->processQuery( q );
        }
    }
}


/*! Returns the query string for \a q, after possibly applying
    version-specific hacks and workarounds. */

EString Postgres::queryString( Query * q )
{
    EString s( q->string() );

    // Postgres 8.1 plans "where x=ANY($1)" with a seqscan, but we can
    // use a grotesque generate_series hack to subvert that behaviour.
    //
    // "x=any($1)" should be rewritten to:
    // "x in (select $1[i] from generate_series(1,array_upper($1,1)))"
    //
    // We add typecasts, and a "LIMIT" in the subquery seems to make
    // Postgres believe that the outer query is selective enough to
    // avoid a seqscan.

    if ( s.contains( "=any($" ) && ::serverVersion < 80200 ) {
        bool ok = true;
        while ( s.contains( "=any($" ) ) {
            EString p( s.section( "=any($", 2 ).section( ")", 1 ) );

            // p looks like "1" or "1::text[]".
            uint v = p.section( "::", 1 ).number( &ok );
            EString type( p.section( "::", 2 ) );

            // Most of the arrays we bind are int[], so we only require
            // the exceptions to specify the type explicitly.
            if ( type.isEmpty() )
                type = "int[]";

            // t should look like "1::int[]" or "1::text[]".
            EString t( fn( v ) );
            t.append( "::" );
            t.append( type );

            if ( !ok )
                break;

            // Now comes the really awful part. We look at the parameter
            // bound to $v, and if it's a one-element array, we rewrite
            // the =any($v) to =$v, and replace the parameter itself.

            bool alone = false;
            List<Query::Value> * values = q->values();
            List<Query::Value>::Iterator it( values );
            while ( it && it->position() != v )
                ++it;
            if ( it ) {
                Query::Value * qv = it;

                // By this time, a List is in {a,b,c} format, so we have
                // to count elements by looking for commas.
                EString l( qv->data() );
                l = l.mid( 1, l.length()-2 );

                // 123 or foo or "f,o": we ignore the last for now.
                if ( !l.contains( "," ) && !l.isEmpty() ) {
                    alone = true;
                    if ( l.isQuoted() )
                        l = l.unquoted();
                    values->insert( it, new Query::Value( qv->position(), l,
                                                          qv->format() ) );
                    (void)values->take( it );
                }
            }

            EString z;

            if ( alone )
                z.append( "=$" + fn( v ) );
            else
                z.append( " in (select ($" + t + ")[i] "
                          "from generate_series(1,array_upper($" + t + ",1)) "
                          "as s(i) limit array_upper($" + t + ",1))" );

            s.replace( "=any($" + p + ")", z );
        }
    }

    if ( s != q->string() ) {
        Scope x( q->log() );
        log( "Changing query string to: " + s, Log::Debug );
    }

    return s;
}


bool Postgres::blocked( const class Transaction * transaction ) const
{
    if ( !transaction )
        return false;

    Transaction * t = d->transaction;
    if ( t == transaction )
        return false;
    while ( t ) {
        t = t->parent();
        if ( t == transaction )
            return true;
    }

    return false;
}


List< Query > * Postgres::activeQueries() const
{
    return & d->queries;
}


class PgCanceller
    : public Postgres
{
private:
    PgKeyData * k;

public:
    PgCanceller( PgKeyData * key )
        : Postgres(), k( key )
    {
        log( "Sending cancel for pid " + fn( k->pid() ), Log::Debug );
    }

    void react( Event e )
    {
        switch (e) {
        case Connect:
            {
                PgCancel msg( k );
                msg.enqueue( writeBuffer() );
                Connection::setState( Closing );
            }
            break;

        default:
            break;
        }
    }
};


/*! Issues a cancel request for the query \a q if it is being executed
    by this Postgres object. If not, it does nothing.
*/

void Postgres::cancel( Query * q )
{
    if ( d->queries.find( q ) )
        (void)new PgCanceller( d->keydata );
}
