// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "postgres.h"

#include "dict.h"
#include "list.h"
#include "string.h"
#include "buffer.h"
#include "allocator.h"
#include "configuration.h"
#include "transaction.h"
#include "stringlist.h"
#include "pgmessage.h"
#include "eventloop.h"
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


class PgData
    : public Garbage
{
public:
    PgData()
        : active( false ), startup( false ), authenticated( false ),
          unknownMessage( false ), identBreakageSeen( false ),
          sendingCopy( false ), error( false ), keydata( 0 ),
          description( 0 ), transaction( 0 )
    {}

    bool active;
    bool startup;
    bool authenticated;
    bool unknownMessage;
    bool identBreakageSeen;
    bool sendingCopy;
    bool error;

    PgKeyData *keydata;
    Dict< String > params;
    PgRowDescription *description;
    Dict< int > prepared;

    List< Query > queries;
    Transaction *transaction;
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
    log()->setFacility( Log::Database );
    log( "Connecting to PostgreSQL server at " + server().string(),
         Log::Debug );

    struct passwd * p = getpwnam( Database::user().cstr() );
    if ( !p )
        p = getpwnam( Configuration::compiledIn( Configuration::PgUser ) );
    if ( !p )
        p = getpwnam( "postgres" );
    if ( !p )
        p = getpwnam( "pgsql" );
    if ( p && getuid() != p->pw_uid ) {
        // Try to cooperate with ident authentication.
        uid_t e = geteuid();
        setreuid( 0, p->pw_uid );
        connect( server() );
        setreuid( 0, e );
    }
    else {
        connect( server() );
    }

    setTimeoutAfter( 10 );
    EventLoop::global()->addConnection( this );
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
        l = d->transaction->queries();

    while ( ( q = l->firstElement() ) != 0 ) {
        if ( q->state() != Query::Submitted )
            break;

        l->shift();
        q->setState( Query::Executing );

        if ( !d->transaction && q->transaction() ) {
            d->transaction = q->transaction();
            d->transaction->setState( Transaction::Executing );
            d->transaction->setDatabase( this );
            l = d->transaction->queries();
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
        }
    }

    if ( n > 0 ) {
        extendTimeout( 5 );
        write();
    }
}


/*! Sends whatever messages are required to make the backend process the
    query \a q.
*/

void Postgres::processQuery( Query * q )
{
    Scope x( q->log() );
    String s( "Sent " );
    if ( q->name() == "" ||
         !d->prepared.contains( q->name() ) )
    {
        PgParse a( q->string(), q->name() );
        a.enqueue( writeBuffer() );

        if ( q->name() != "" )
            d->prepared.insert( q->name(), 0 );
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
    s.append( fn( connectionNumber() ) );
    ::log( s, Log::Debug );
    recordExecution();
}


void Postgres::react( Event e )
{
    switch ( e ) {
    case Connect:
        {
            PgStartup msg;
            msg.setOption( "user", user() );
            msg.setOption( "database", name() );
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
                error( "Malformed '" + String( &msg, 1 ) +
                       "' message received." );
            }
        }

        if ( !busy() ) {
            processQueue();
            if ( d->queries.isEmpty() ) {
                uint interval =
                    Configuration::scalar( Configuration::DbHandleInterval );
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
        break;

    case Timeout:
        if ( !d->active || d->startup ) {
            error( "Timeout negotiating connection to PostgreSQL." );
        }
        else if ( d->queries.count() > 0 ) {
            error( "Request timeout." );
        }
        else if ( d->transaction ) {
            d->transaction->setError( 0, "Transaction timeout" );
            d->transaction->rollback();
        }
        else if ( numHandles() > 3 && server().protocol() != Endpoint::Unix ) {
            shutdown();
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
                    String pass = password();

                    if ( r.type() == PgAuthRequest::Crypt )
                        pass = ::crypt( pass.cstr(), r.salt().cstr() );
                    else if ( r.type() == PgAuthRequest::MD5 )
                        pass = "md5" + MD5::hash(
                                           MD5::hash(
                                               pass + user()
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

        commit();
        break;

    case 'K':
        d->keydata = new PgKeyData( readBuffer() );
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

            // We could suppress this notification if we could somehow
            // infer that we will receive a completion message soon.

            PgDataRow msg( readBuffer(), d->description );
            q->addRow( msg.row() );
            q->notify();
        }
        break;

    case 'I':
    case 'C':
        {
            if ( type == 'C' )
                PgCommandComplete msg( readBuffer() );
            else
                PgEmptyQueryResponse msg( readBuffer() );

            if ( q ) {
                String s;
                s.append( "Dequeueing query " );
                s.append( q->description() );
                s.append( " on backend " );
                s.append( fn( connectionNumber() ) );
                if ( q->rows() > 0 ) {
                    s.append( " (with " );
                    s.append( fn( q->rows() ) );
                    s.append( " rows)" );
                }
                ::log( s, Log::Debug );
                if ( !q->done() )
                    q->setState( Query::Completed );
                d->queries.shift();
                q->notify();
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
                    d->transaction = 0;
                }
            }

            setState( msg.state() );

        }
        commit();
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
    String s;

    switch ( type ) {
    case 'S':
        {
            d->unknownMessage = false;
            PgParameterStatus msg( readBuffer() );
            d->params.insert( msg.name(), new String( msg.value() ) );
        }
        break;

    case 'N':
    case 'E':
        {
            d->unknownMessage = false;
            PgMessage msg( readBuffer() );
            Query *q = d->queries.firstElement();

            switch ( msg.severity() ) {
            case PgMessage::Panic:
            case PgMessage::Fatal:
                // special-case IDENT query failures since they can be
                // so off-putting to novices.
                if ( msg.message().lower().startsWith( "ident authentication "
                                                       "failed for user \"") ) {
                    String s = msg.message();
                    int b = s.find( '"' );
                    int e = s.find( '"', b+1 );
                    s = s.mid( b+1, e-b-1 ); // rest-of-string if e==-1 ;)
                    if ( s == Configuration::text(Configuration::JailUser) &&
                         self().protocol() != Endpoint::Unix &&
                         Configuration::toggle( Configuration::Security ) &&
                         !d->identBreakageSeen ) {
                        // If we connected via ipv4 or ipv6, and we
                        // did it so early that postgres had a chance
                        // to reject us, we can try again. We do that
                        // only once, and only if we believe it may
                        // succeed.
                        d->identBreakageSeen = true;
                        log( "PostgreSQL demanded IDENT, "
                             "which did not match during startup. Retrying.",
                             Log::Info );
                        Endpoint pg( peer() );
                        close();
                        connect( pg );
                    }
                    else {
                        log( "PostgreSQL refuses authentication because this "
                             "process is not running as user " + s + ". See "
                             "http://aox.org/faq/mailstore.html#ident",
                             Log::Disaster );
                    }
                }
                else {
                    if ( msg.severity() == PgMessage::Panic )
                        s.append( "PANIC: " );
                    else
                        s.append( "FATAL: " );
                    s.append( msg.message() );
                    error( s );
                }
                break;

            case PgMessage::Error:
            case PgMessage::Warning:
                if ( msg.severity() == PgMessage::Warning )
                    s.append( "WARNING: " );
                else
                    s.append( "ERROR: " );

                if ( q )
                    s.append( "Query " + q->description() + ": " );

                s.append( msg.message() );
                if ( msg.detail() != "" )
                    s.append( " (" + msg.detail() + ")" );

                if ( !q ||
                     !( q->canFail() ||
                        ( q->transaction() && q->transaction()->failed() ) ) )
                    ::log( s, Log::Error );

                // Has the current query failed?
                if ( q && msg.severity() == PgMessage::Error ) {
                    if ( q->inputLines() )
                        d->sendingCopy = false;
                    d->queries.shift();
                    q->setError( msg.message() );
                    q->notify();
                }
                break;

            default:
                ::log( msg.message(), Log::Debug );
                break;
            }
        }
        break;

    default:
        {
            String err = "Unexpected message (";

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


/*! Handles all protocol/socket errors by logging the error message \a s
    and closing the connection after flushing the write buffer and
    notifying any pending queries of the failure.
*/

void Postgres::error( const String &s )
{
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

    if ( d->transaction ) {
        d->transaction->setError( 0, "Database connection shutdown" );
        d->transaction->notify();
    }
    List< Query >::Iterator q( d->queries );
    while ( q ) {
        q->setError( "Database connection shutdown" );
        q->notify();
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


/*! Returns true if at least one Query has been sent to the Postgres
    server and not yet completely processed by the server.
*/

bool Postgres::busy() const
{
    return !d->queries.isEmpty();
}
