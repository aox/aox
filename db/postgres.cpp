#include "postgres.h"

#include "event.h"
#include "query.h"
#include "string.h"
#include "buffer.h"
#include "list.h"
#include "dict.h"
#include "loop.h"
#include "md5.h"
#include "log.h"
#include "pgmessage.h"
#include "transaction.h"

// crypt
#define _XOPEN_SOURCE
#include <unistd.h>


class PgData {
public:
    PgData()
        : l( new Log( Log::Database ) ), status( Idle ),
          active( false ), startup( false ), authenticated( false ),
          reserved( false ), unknownMessage( false ),
          keydata( 0 ), description( 0 ), transaction( 0 )
    {}

    Log *l;

    Status status;

    bool active;
    bool startup;
    bool authenticated;

    bool reserved;
    bool unknownMessage;

    PgKeyData *keydata;
    Dict< String > params;
    PgRowDescription *description;
    Dict< int > prepared;

    List< Query > queries;
    List< Query > pending;
    Transaction *transaction;
};


/*! \class Postgres postgres.h
    Implements the PostgreSQL 3.0 Frontend-Backend protocol.

    This is our interface to PostgreSQL. As a subclass of Database, it
    accepts Query objects, sends queries to the database, and notifies
    callers about any resulting data. As a descendant of Connection, it
    is responsible for all network communications with the server.

    The network protocol is documented at <doc/src/sgml/protocol.sgml>
    and <http://developer.postgresql.org/docs/postgres/protocol.html>.
    The version implemented here is used by PostgreSQL 7.4 and later.

    At the time of writing, there do not seem to be any other suitable
    PostgreSQL client libraries freely available. For example, libpqxx
    doesn't support asynchronous operation or prepared statements. Its
    interface would be difficult to wrap in a database-agnostic manner,
    and it depends on the untested libpq. The others aren't much better.
*/

/*! Creates a Postgres object, initiates a TCP connection to the server,
    registers with the main loop, and adds this Database to the list of
    available handles.
*/

Postgres::Postgres()
    : Database(), d( new PgData )
{
    connect( Database::server() );
    Loop::addConnection( this );
    Database::addHandle( this );
    setTimeoutAfter( 60 );
}


Postgres::~Postgres()
{
    Loop::removeConnection( this );
}


bool Postgres::ready()
{
    return d->pending.count() <= 5 && !d->reserved;
}


void Postgres::enqueue( Query *q )
{
    if ( q->transaction() != 0 )
        d->reserved = true;
    d->pending.append( q );
}


void Postgres::execute()
{
    List< Query >::Iterator it( d->pending.first() );

    if ( !it )
        return;

    if ( !d->active || d->startup ) {
        while ( it ) {
            it->setState( Query::Submitted );
            it++;
        }
        return;
    }

    processQueue( true );
}


void Postgres::react( Event e )
{
    switch ( e ) {
    case Connect:
        {
            PgStartup msg;
            msg.setOption( "user", Database::user() );
            msg.setOption( "database", Database::name() );
            msg.enqueue( writeBuffer() );

            d->active = true;
            d->startup = true;
        }
        break;

    case Read:
        while ( d->active && haveMessage() ) {
            /* We call a function to process every message we receive.
               This function is expected to parse and remove a message
               from the readBuffer, throwing an exception for malformed
               messages, and setting d->unknownMessage for messages that
               it can't or won't handle. */

            try {
                char msg = (*readBuffer())[0];

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
                error( "Malformed message received." );
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
        break;

    case Shutdown:
        {
            PgTerminate msg;
            msg.enqueue( writeBuffer() );
            Database::removeHandle( this );
            setState( Closing );

            d->active = false;
        }
        break;
    }

    d->l->commit();
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
                    String pass = Database::password();

                    if ( r.type() == PgAuthRequest::Crypt )
                        pass = ::crypt( pass.cstr(), r.salt().cstr() );
                    else if ( r.type() == PgAuthRequest::MD5 )
                        pass = "md5" + MD5::hash(
                                           MD5::hash(
                                               pass + Database::user()
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
        // This successfully concludes connection startup. We'll leave
        // this message unparsed, so that process() can handle it like
        // any other PgReady.
        setTimeout( 0 );
        log( "PostgreSQL: Ready for queries" );
        d->startup = false;
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
    List< Query >::Iterator q = d->queries.first();

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

    case 'T':
        d->description = new PgRowDescription( readBuffer() );
        break;

    case 'D':
        {
            PgDataRow msg( readBuffer() );

            if ( !q || !d->description ) {
                error( "Unexpected data row" );
                return;
            }

            // We could suppress this notification if we could somehow
            // infer that we will receive a completion message soon.

            q->addRow( composeRow( msg ) );
            q->notify();
        }
        break;

    case 'I':
        {
            PgEmptyQueryResponse msg( readBuffer() );
        }
        break;

    case 'C':
        {
            PgCommandComplete msg( readBuffer() );
        }
        break;

    case 'Z':
        {
            PgReady msg( readBuffer() );
            d->status = msg.status();

            if ( d->transaction ) {
                if ( d->status == Idle && q->transaction() != 0 ) {
                    d->transaction->setState( Transaction::Completed );
                    d->reserved = false;
                    d->transaction = 0;
                }
                else if ( d->status == Failed ) {
                    d->transaction->setState( Transaction::Failed );
                }
            }

            if ( q ) {
                q->setState( Query::Completed );
                q->notify();
                d->queries.take( q );
            }

            processQueue();
            if ( d->queries.isEmpty() )
                setTimeout( 0 );
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
            PgParameterStatus msg( readBuffer() );
            d->unknownMessage = false;
            d->params.insert( msg.name(), new String( msg.value() ) );
        }
        break;

    case 'N':
    case 'E':
        {
            PgMessage msg( readBuffer() );

            switch ( msg.severity() ) {
            case PgMessage::Panic:
            case PgMessage::Fatal:
                error( msg.message() );
                break;

            case PgMessage::Error:
                {
                    Query * q = d->queries.take( d->queries.first() );
                    q->setError( msg.message() );
                    q->notify();
                }
                break;

            default:
                log( msg.message() );
                break;
            }

            d->unknownMessage = false;
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
    log( Log::Error, s );
    d->l->commit();

    List< Query >::Iterator q( d->queries.first() );
    while ( q ) {
        q->setError( s );
        q->notify();
        q++;
    }

    q = d->pending.first();
    while ( q ) {
        q->setError( s );
        q->notify();
        q++;
    }

    writeBuffer()->remove( writeBuffer()->size() );
    writeBuffer()->remove( writeBuffer()->size() );
    Database::removeHandle( this );
    setState( Closing );
}


/*! Returns true only if there is a complete message in our read buffer. */

bool Postgres::haveMessage()
{
    Buffer * b = readBuffer();

    if ( b->size() < 5 ||
         b->size() < 1+( (uint)(*b)[1]>>24|(*b)[2]>>16|(*b)[3]>>8|(*b)[4] ) )
        return false;
    return true;
}


/*! This is the function that actually composes queries and sends them
    to the server. If \a userContext is true, it processes all pending
    queries. If not, it stops at the first one whose Query::state() is
    not Query::Submitted.
*/

void Postgres::processQueue( bool userContext )
{
    List< Query >::Iterator it( d->pending.first() );

    if ( !it )
        return;

    while ( it ) {
        if ( !userContext && it->state() != Query::Submitted )
            break;

        Query *q = d->pending.take( it );
        q->setState( Query::Executing );
        d->queries.append( q );

        if ( d->transaction == 0 && q->transaction() != 0 ) {
            d->transaction = q->transaction();
            d->transaction->setState( Transaction::Executing );
            PgParse a( "begin" );
            a.enqueue( writeBuffer() );

            PgBind b;
            b.enqueue( writeBuffer() );

            PgExecute c;
            c.enqueue( writeBuffer() );
        }

        if ( q->name() == "" ||
             !d->prepared.contains( q->name() ) )
        {
            PgParse a( q->string(), q->name() );
            a.enqueue( writeBuffer() );

            if ( q->name() != "" )
                d->prepared.insert( q->name(), 0 );
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
    }

    if ( writeBuffer()->size() > 0 )
        extendTimeout( 5 );
    write();
}


/*! Returns a Row object constructed from the DataRow message \a r. */

Row *Postgres::composeRow( const PgDataRow &r )
{
    List< PgRowDescription::Column >::Iterator c;
    List< PgDataRow::Value >::Iterator v;
    Row *row = new Row();

    c = d->description->columns.first();
    v = r.columns.first();
    while ( c ) {
        Row::Column *cv = new Row::Column;

        Database::Type t;
        switch ( c->type ) {
        case 16:    // BOOL
            t = Database::Boolean;
            break;
        case 21:    // INT2
        case 23:    // INT4
            t = Database::Integer;
            break;
        case 17:    // BYTEA
        case 18:    // CHAR
        case 1043:  // VARCHAR
            t = Database::Bytes;
            break;
        default:
            t = Database::Unknown;
            break;
        }

        cv->name = c->name;
        cv->type = t;
        cv->length = v->length;
        cv->value = v->value;
        row->append( cv );

        c++;
        v++;
    }

    return row;
}


static int currentRevision = 3;

class UpdateSchema : public EventHandler {
private:
    int state;
    int substate;
    int revision;
    Transaction *t;
    Query *lock, *seq, *update, *q;

public:
    UpdateSchema()
        : state( 0 ), substate( 0 )
    {}

    void execute();
};

void UpdateSchema::execute() {
    // Find and lock the current schema revision.
    if ( state == 0 ) {
        t = new Transaction( this );
        lock = new Query( "select revision from mailstore for update",
                          this );
        t->enqueue( lock );
        t->execute();
        state = 1;
    }
    if ( state == 1 ) {
        if ( !lock->done() )
            return;
        revision = lock->nextRow()->getInt( "revision" );

        if ( revision == currentRevision ) {
            state = 7;
            t->commit();
        }
        else if ( revision > currentRevision ) {
            log( Log::Disaster,
                 "The schema is newer than this server expected. Upgrade." );
            state = 8;
            return;
        }
        else {
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
                log( Log::Disaster,
                     "Can't update, because an earlier schema update failed." );
                state = 8;
                break;
            }
            state = 4;
        }
        if ( state == 4 ) {
            if ( revision == 1 ) {
                if ( substate == 0 ) {
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
                    substate = 0;
                }
            }

            if ( revision == 2 ) {
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
                state = 7;
                break;
            }
            state = 2;
        }
    }

    if ( state == 7 ) {
        if ( !t->done() )
            return;

        if ( t->failed() ) {
            log( Log::Disaster,
                 "The schema update transaction failed unexpectedly." );
            state = 8;
        }
    }

    if ( state == 8 ) {
        // This is a disaster. But do we need to do anything here?
    }
}


/*! This static function determines the current schema version, and if
    required, updates it to the current version.
*/

void Postgres::updateSchema()
{
    UpdateSchema *s = new UpdateSchema;
    s->execute();
}
