// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "postgres.h"

#include "dict.h"
#include "list.h"
#include "string.h"
#include "buffer.h"
#include "configuration.h"
#include "transaction.h"
#include "stringlist.h"
#include "pgmessage.h"
#include "query.h"
#include "event.h"
#include "loop.h"
#include "md5.h"
#include "log.h"

// crypt
#define _XOPEN_SOURCE 4
#include <unistd.h>


static bool hasMessage( Buffer * );


class PgData {
public:
    PgData()
        : active( false ), startup( false ), authenticated( false ),
          unknownMessage( false ), identBreakageSeen( false ),
          keydata( 0 ), description( 0 ), transaction( 0 )
    {}

    bool active;
    bool startup;
    bool authenticated;
    bool unknownMessage;
    bool identBreakageSeen;

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
    connect( server() );
    setTimeoutAfter( 60 );
    Loop::addConnection( this );
    addHandle( this );
}


Postgres::~Postgres()
{
    Loop::removeConnection( this );
}


void Postgres::processQueue()
{
    Query *q;
    int n = 0;

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

        d->queries.append( q );

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

        PgExecute d;
        d.enqueue( writeBuffer() );

        PgSync e;
        e.enqueue( writeBuffer() );

        s.append( "execute for " );
        s.append( q->description() );
        log( s, Log::Debug );
        n++;
    }

    if ( n > 0 ) {
        extendTimeout( 5 );
        write();
    }
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
        break;

    case Error:
        error( "Couldn't connect to PostgreSQL." );
        break;

    case Close:
        error( "Connection terminated by the server." );
        break;

    case Timeout:
        if ( !d->active || d->startup )
            error( "Timeout negotiating connection to PostgreSQL." );
        else if ( d->queries.count() > 0 )
            error( "Request timeout." );
        else if ( numHandles() > 1 || server().protocol() != Endpoint::Unix )
            shutdown();
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
    static bool initialized = false;
    switch ( type ) {
    case 'Z':
        setTimeout( 0 );
        d->startup = false;

        // The first time we successfully negotiate a connection, we
        // need to run updateSchema.
        if ( !initialized ) {
            initialized = true;
            updateSchema();
            log( "PostgreSQL: Ready for queries" );
        }

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
    Query *q = d->queries.firstElement();

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
                s.append( "Dequeueing query " + q->description() );
                if ( q->rows() > 0 )
                    s.append( " (with " + fn( q->rows() ) + " rows)" );
                log( s, Log::Debug );
                if ( !q->done() )
                    q->setState( Query::Completed );
                q->notify();
                d->queries.shift();
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

            processQueue();
            if ( d->queries.isEmpty() ) {
                uint interval =
                    Configuration::scalar( Configuration::DbHandleInterval );
                setTimeoutAfter( interval );
            }
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
                if ( msg.message().startsWith( "IDENT authentication "
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
                             "process is not running as user " + s,
                             Log::Disaster );
                        log( "See "
                             "http://www.oryx.com/faq/mailstore.html#ident",
                             Log::Info );
                    }
                }
                else {
                    error( msg.message() );
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

                if ( !q || !q->canFail() )
                    log( s, Log::Error );

                // Has the current query failed?
                if ( q && msg.severity() == PgMessage::Error ) {
                    d->queries.shift();
                    q->setError( msg.message() );
                    q->notify();
                }
                break;

            default:
                log( msg.message(), Log::Debug );
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
    d->active = false;
    log( s, Log::Error );

    List< Query >::Iterator q( d->queries );
    while ( q ) {
        q->setError( s );
        q->notify();
        ++q;
    }

    writeBuffer()->remove( writeBuffer()->size() );
    writeBuffer()->remove( writeBuffer()->size() );
    Connection::setState( Closing );
    removeHandle( this );
}


/*! Sends a termination message and takes this database handle out of
    circulation gracefully.
*/

void Postgres::shutdown()
{
    PgTerminate msg;
    msg.enqueue( writeBuffer() );
    removeHandle( this );

    d->active = false;
}


static int currentRevision = 6;


class UpdateSchema
    : public EventHandler
{
private:
    int state;
    int substate;
    int revision;
    Transaction *t;
    Query *lock, *seq, *update, *q;
    Log *l;

public:
    UpdateSchema()
        : state( 0 ), substate( 0 ), revision( 0 ),
          t( new Transaction( this ) ),
          l( new Log( Log::Database ) )
    {}

    Transaction *transaction() const { return t; }
    void execute();
};


void UpdateSchema::execute() {
    // Find and lock the current schema revision.
    if ( state == 0 ) {
        lock = new Query( "select revision from mailstore for update",
                          this );
        t->enqueue( lock );
        t->execute();
        state = 1;
    }

    if ( state == 1 ) {
        if ( !lock->done() )
            return;

        Row *r = lock->nextRow();
        if ( lock->failed() || !r ) {
            l->log( "Database inconsistent: "
                    "Couldn't query the mailstore table.",
                    Log::Disaster );
            return;
        }

        revision = r->getInt( "revision" );
        if ( revision == currentRevision ) {
            state = 7;
            t->commit();
        }
        else if ( revision > currentRevision ) {
            l->log( "The schema is newer than this server expected. "
                    "Schema revision " + fn( revision ) +
                    ", supported revision " + fn( currentRevision ) +
                    ", server version " +
                    Configuration::compiledIn( Configuration::Version ) +
                    ". Please upgrade or consult support.",
                    Log::Disaster );
            state = 9;
            return;
        }
        else {
            l->log( "Updating schema from revision " + fn( revision ) +
                    " to revision " + fn( currentRevision ) );
            state = 2;
        }
    }

    // Perform successive updates towards the current revision.
    while ( revision < currentRevision ) {
        if ( state == 2 ) {
            seq = new Query( "select nextval('revisions')::integer as seq",
                             this );
            t->enqueue( seq );
            t->execute();
            state = 3;
        }
        if ( state == 3 ) {
            if ( !seq->done() )
                return;
            int gap = seq->nextRow()->getInt( "seq" ) - revision;
            if ( gap > 1 ) {
                l->log( "Can't update because an earlier schema update failed.",
                        Log::Disaster );
                state = 9;
                break;
            }
            state = 4;
        }
        if ( state == 4 ) {
            if ( revision == 1 ) {
                if ( substate == 0 ) {
                    l->log( "Changing users.login/secret to text", Log::Debug );
                    q = new Query( "alter table users add login2 text", this );
                    t->enqueue( q );
                    q = new Query( "update users set login2=login", this );
                    t->enqueue( q );
                    q = new Query( "alter table users drop login", this );
                    t->enqueue( q );
                    q = new Query( "alter table users rename login2 to login",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table users add unique(login)",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table users add secret2 text", this );
                    t->enqueue( q );
                    q = new Query( "update users set secret2=secret", this );
                    t->enqueue( q );
                    q = new Query( "alter table users drop secret", this );
                    t->enqueue( q );
                    q = new Query( "alter table users rename secret2 to secret",
                                   this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 2 ) {
                if ( substate == 0 ) {
                    l->log( "Merging bodyparts and binary_parts", Log::Debug );
                    q = new Query( "alter table bodyparts add hash text",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table bodyparts add data bytea",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table bodyparts add text2 text",
                                   this );
                    t->enqueue( q );
                    q = new Query( "update bodyparts set data=b.data from "
                                   "binary_parts b where id=b.bodypart",
                                   this );
                    t->enqueue( q );
                    q = new Query( "declare parts cursor for "
                                   "select id,text,data from bodyparts",
                                   this );
                    t->enqueue( q );
                    q = new Query( "fetch 512 from parts", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    while ( q->hasResults() ) {
                        Row *r = q->nextRow();
                        String text, data;

                        Query *u =
                            new Query( "update bodyparts set "
                                       "text2=$1,hash=$2 where id=$3", this );
                        if ( r->isNull( "text" ) ) {
                            data = r->getString( "data" );
                            u->bindNull( 1 );
                            u->bind( 2, MD5::hash( data ).hex() );
                        }
                        else {
                            text = r->getString( "text" );
                            u->bind( 1, text );
                            u->bind( 2, MD5::hash( text ).hex() );
                        }
                        u->bind( 3, r->getInt( "id" ) );
                        t->enqueue( u );
                    }

                    if ( !q->done() )
                        return;

                    if ( q->rows() != 0 ) {
                        q = new Query( "fetch 512 from parts", this );
                        t->enqueue( q );
                        t->execute();
                        return;
                    }
                    else {
                        substate = 2;
                        t->enqueue( new Query( "close parts", this ) );
                    }
                }

                if ( substate == 2 ) {
                    q = new Query( "alter table bodyparts drop text", this );
                    t->enqueue( q );
                    q = new Query( "alter table bodyparts rename text2 to text",
                                   this );
                    t->enqueue( q );
                    q = new Query( "select id,hash from bodyparts where hash in "
                                   "(select hash from bodyparts group by hash"
                                   " having count(*) > 1)", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 3;
                }

                if ( substate == 3 ) {
                    if ( !q->done() )
                        return;

                    StringList ids;
                    Dict< uint > hashes;

                    while ( q->hasResults() ) {
                        Row *r = q->nextRow();
                        uint id = r->getInt( "id" );
                        String hash = r->getString( "hash" );

                        uint *old = hashes.find( hash );
                        if ( old ) {
                            ids.append( fn( id ) );
                            Query *u =
                                new Query( "update part_numbers set "
                                           "bodypart=$1 where bodypart=$2",
                                           this );
                            u->bind( 1, *old );
                            u->bind( 2, id );
                            t->enqueue( u );
                        }
                        else {
                            hashes.insert( hash, new uint( id ) );
                        }
                    }

                    if ( !ids.isEmpty() ) {
                        q = new Query( "delete from bodyparts where id in "
                                       "(" + ids.join(",") + ")", this );
                        t->enqueue( q );
                    }
                    q = new Query( "drop table binary_parts", this );
                    t->enqueue( q );
                    q = new Query( "alter table bodyparts add unique(hash)",
                                   this );
                    t->enqueue( q );
                    t->execute();
                    substate = 4;
                }

                if ( substate == 4 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 3 ) {
                if ( substate == 0 ) {
                    l->log( "Creating flags from messages/extra_flags.",
                            Log::Debug );
                    q = new Query( "alter table extra_flags rename to flags",
                                   this );
                    t->enqueue( q );
                    q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    q->bind( 1, "\\Deleted" );
                    t->enqueue( q );
                    q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    q->bind( 1, "\\Answered" );
                    t->enqueue( q );
                    q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    q->bind( 1, "\\Flagged" );
                    t->enqueue( q );
                    q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    q->bind( 1, "\\Draft" );
                    t->enqueue( q );
                    q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    q->bind( 1, "\\Seen" );
                    t->enqueue( q );
                    q = new Query( "insert into flags (mailbox,uid,flag) "
                                   "select mailbox,uid,"
                                   "(select id from flag_names"
                                   " where name='\\Deleted') from messages "
                                   "where deleted", this );
                    t->enqueue( q );
                    q = new Query( "insert into flags (mailbox,uid,flag) "
                                   "select mailbox,uid,"
                                   "(select id from flag_names"
                                   " where name='\\Answered') from messages "
                                   "where answered", this );
                    t->enqueue( q );
                    q = new Query( "insert into flags (mailbox,uid,flag) "
                                   "select mailbox,uid,"
                                   "(select id from flag_names"
                                   " where name='\\Flagged') from messages "
                                   "where flagged", this );
                    t->enqueue( q );
                    q = new Query( "insert into flags (mailbox,uid,flag) "
                                   "select mailbox,uid,"
                                   "(select id from flag_names"
                                   " where name='\\Draft') from messages "
                                   "where draft", this );
                    t->enqueue( q );
                    q = new Query( "insert into flags (mailbox,uid,flag) "
                                   "select mailbox,uid,"
                                   "(select id from flag_names"
                                   " where name='\\Seen') from messages "
                                   "where seen", this );
                    t->enqueue( q );
                    q = new Query( "alter table messages drop deleted", this );
                    t->enqueue( q );
                    q = new Query( "alter table messages drop answered", this );
                    t->enqueue( q );
                    q = new Query( "alter table messages drop flagged", this );
                    t->enqueue( q );
                    q = new Query( "alter table messages drop draft", this );
                    t->enqueue( q );
                    q = new Query( "alter table messages drop seen", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 4 ) {
                if ( substate == 0 ) {
                    l->log( "Adding hf_mup, af_mu, fl_mu indices.",
                            Log::Debug );
                    q = new Query( "create index hf_mup on "
                                   "header_fields (mailbox,uid,part)", this );
                    t->enqueue( q );
                    q = new Query( "create index af_mu on "
                                   "address_fields (mailbox,uid)", this );
                    t->enqueue( q );
                    q = new Query( "create index fl_mu on "
                                   "flags (mailbox,uid)", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 5 ) {
                if ( substate == 0 ) {
                    l->log( "Moving bytes/lines to part_numbers.",
                            Log::Debug );
                    q = new Query( "alter table part_numbers add "
                                   "bytes integer", this );
                    t->enqueue( q );
                    q = new Query( "alter table part_numbers add "
                                   "lines integer", this );
                    t->enqueue( q );
                    q = new Query( "update part_numbers set "
                                   "bytes=bodyparts.bytes,"
                                   "lines=bodyparts.lines from "
                                   "bodyparts where "
                                   "part_numbers.bodypart=bodyparts.id",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table bodyparts drop lines",
                                   this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }
            }

            state = 5;
        }
        if ( state == 5 ) {
            update = new Query( "update mailstore set revision=revision+1",
                                this );
            t->enqueue( update );
            t->execute();
            state = 6;
        }
        if ( state == 6 ) {
            if ( !update->done() )
                return;

            revision = revision+1;
            if ( revision == currentRevision ) {
                t->commit();
                state = 8;
                break;
            }
            state = 2;
        }
    }

    if ( state == 7 || state == 8 ) {
        if ( !t->done() )
            return;

        if ( t->failed() ) {
            l->log( "The schema update transaction failed.", Log::Disaster );
            state = 9;
        }
        else if ( state == 8 ) {
            l->log( "Schema updated to revision " + fn( currentRevision ) );
        }
    }

    if ( state == 9 ) {
        // This is a disaster. But do we need to do anything here?
    }
}


/*! This static function determines the current schema version, and if
    required, updates it to the current version.
*/

void Postgres::updateSchema()
{
    UpdateSchema *s = new UpdateSchema;

    d->transaction = s->transaction();
    d->transaction->setDatabase( this );
    s->execute();
}


static bool hasMessage( Buffer *b )
{
    if ( b->size() < 5 ||
         b->size() < 1+( (uint)((*b)[1]<<24)|((*b)[2]<<16)|
                               ((*b)[3]<<8)|((*b)[4]) ) )
        return false;
    return true;
}
