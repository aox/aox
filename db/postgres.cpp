#include "postgres.h"

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

#define _XOPEN_SOURCE
#include <time.h>
#include <unistd.h>


class PgData {
public:
    PgData()
        : l( new Log ),
          active( false ), startup( false ), authenticated( false ),
          unknownMessage( false ), transaction( 0 ),
          transactionSubmitted( false )
    {}

    Log *l;

    bool active;
    bool startup;
    bool authenticated;
    bool unknownMessage;

    PgKeyData *keydata;
    Dict< String > params;
    PgRowDescription *description;
    PgReady::Status status;

    List< Query > queries;
    Transaction *transaction;
    bool transactionSubmitted;
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
    setTimeout( time(0) + 10 );
}


/*! Returns true only if this object is ready to accept another query.
*/

bool Postgres::ready()
{
    /* We would prefer to accept queries only after connecting to the
       server, but we accept them earlier in order to avoid orphaned
       queries that will not be notified if we can't connect. */

    return d->queries.count() <= 3 && !d->transactionSubmitted;
}


/*! This function adds a \a query to this object's queue, and sends it
    to the database immediately if no other query is outstanding. The
    state of \a query is set to Query::Executing if it was sent, and
    to Query::Submitted if it was queued for later transmission.

    Don't submit a query unless this Database is ready() for one.
*/

void Postgres::submit( Query *query )
{
    if ( query->transaction() != 0 )
        d->transactionSubmitted = true;

    d->queries.append( query );
    query->setState( Query::Submitted );
    if ( d->queries.count() == 1 )
        processQuery( query );
}


/*! This function adds \a ps to this object's queue and sets its state
    to Query::Preparing. It behaves like submit().
*/

void Postgres::prepare( PreparedStatement *ps )
{
    d->queries.append( ps );
    ps->setState( Query::Preparing );
    if ( d->queries.count() == 1 )
        processQuery( ps );
}


/*! \reimp */

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
        d->l->log( "PostgreSQL: Ready for queries" );
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

    if ( timeout() != 0 )
        setTimeout( timeout() + 5 );

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
            PgEmptyQueryResponse m( readBuffer() );
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
                if ( d->status == PgReady::Idle ) {
                    d->transaction->setState( Transaction::Completed );
                    d->transactionSubmitted = false;
                    d->queries.take( q );
                    d->transaction = 0;
                    return;
                }
                else if ( d->status == PgReady::Failed ) {
                    d->transaction->setState( Transaction::Failed );
                }
            }

            if ( !q )
                return;

            if ( q->state() == Query::Executing ||
                 q->state() == Query::Preparing )
            {
                q->setState( Query::Completed );
                q->notify();
                d->queries.take( q );
            }

            if ( q )
                processQuery( q );
            else
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
                    d->unknownMessage = false;
                }
                break;

            default:
                d->l->log( msg.message() );
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
                err.append( "%" + String::fromNumber( (int)type, 16 ) );

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
    d->l->log( Log::Error, s );
    d->l->commit();

    List< Query >::Iterator q = d->queries.first();
    while ( q ) {
        q->setError( s );
        q->notify();
        q++;
    }

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


/*! Translates \a query into a series of Postgres messages and sends
    them to the server.
*/

void Postgres::processQuery( Query *query )
{
    if ( !d->active || d->startup )
        return;

    if ( query->state() == Query::Preparing ) {
        PgParse a( query->string(), query->name() );
        PgSync b;

        a.enqueue( writeBuffer() );
        b.enqueue( writeBuffer() );
    }
    else if ( !query->values()->isEmpty() ) {
        query->setState( Query::Executing );

        if ( d->transaction == 0 && query->transaction() != 0 ) {
            d->transaction = query->transaction();
            d->transaction->setState( Transaction::Executing );
            PgParse a( "begin" );
            PgBind b;
            PgExecute c;

            a.enqueue( writeBuffer() );
            b.enqueue( writeBuffer() );
            c.enqueue( writeBuffer() );
        }

        if ( query->name() == "" ) {
            PgParse a( query->string() );
            a.enqueue( writeBuffer() );
        }

        PgBind b( query->name() );
        b.bind( query->values() );
        PgDescribe c;
        PgExecute d;
        PgSync e;

        b.enqueue( writeBuffer() );
        c.enqueue( writeBuffer() );
        d.enqueue( writeBuffer() );
        e.enqueue( writeBuffer() );
    }
    else {
        query->setState( Query::Executing );
        PgQuery pq( query->string() );
        pq.enqueue( writeBuffer() );
    }

    if ( timeout() == 0 )
        setTimeout( time(0) + 5 );
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
        case 16:
            t = Database::Boolean; break;
        case 18:
            t = Database::Character; break;
        case 23:
            t = Database::Integer; break;
        case 1043:
            t = Database::Varchar; break;
        default:
            t = Database::Unknown; break;
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
