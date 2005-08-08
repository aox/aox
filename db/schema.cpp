// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "schema.h"

#include "log.h"
#include "query.h"
#include "transaction.h"


int currentRevision = 9;


class SchemaData
    : public Garbage
{
public:
    SchemaData()
        : l( new Log( Log::Database ) ),
          state( 0 ), lock( 0 ), t( 0 ),
          result( 0 )
    {}

    Log *l;
    int state;
    Query *lock;
    Transaction *t;

    Query *result;
};


/*! \class Schema schema.h
    This class represents the Oryx database schema.

    The static check() function verifies during server startup that the
    running server is compatible with the existing schema.

    The static upgrade() function is used to upgrade the schema to a new
    version.
*/


/*! Creates a new Schema object for \a owner. */

Schema::Schema( EventHandler * owner )
    : d( new SchemaData )
{
    d->result = new Query( owner );
    d->t = new Transaction( this );
}


/*! Checks or upgrades the schema as required. */

void Schema::execute()
{
    if ( d->state == 0 ) {
        d->lock = new Query( "select revision from mailstore for update",
                             this );
        d->t->enqueue( d->lock );
        d->t->commit();
        d->state = 1;
    }

    if ( d->state == 1 ) {
        if ( !d->t->done() )
            return;

        Row *r = d->lock->nextRow();
        if ( d->lock->failed() || !r ) {
            d->l->log( "Database inconsistent: "
                       "Couldn't query the mailstore table.",
                       Log::Disaster );
            d->state = 2;
            d->result->setState( Query::Failed );
            d->result->notify();
            return;
        }

        int revision = r->getInt( "revision" );
        if ( revision == currentRevision ) {
            d->state = 2;
            d->result->setState( Query::Completed );
            d->result->notify();
            return;
        }

        String s( "The existing schema (revision #" );
        s.append( fn( revision ) );
        s.append( ") is " );
        if ( revision < currentRevision )
            s.append( "older" );
        else
            s.append( "newer" );
        s.append( " than this server (version " );
        s.append( Configuration::compiledIn( Configuration::Version ) );
        s.append( ") expected (revision #" );
        s.append( fn( currentRevision ) );
        s.append( "). Please " );
        if ( revision < currentRevision )
            s.append( "run 'ms migrate'" );
        else
            s.append( "upgrade" );
        s.append( " or contact support." );
        d->l->log( s, Log::Disaster );
        d->state = 2;
        d->result->setState( Query::Failed );
        d->result->notify();
    }
}


/*! This function is responsible for checking that the running server is
    compatible with the existing database schema, and to notify \a owner
    when the verification is complete. The return value is a query whose
    state reflects the success or failure of the verification.

    If the schema is not compatible, a disaster is logged.

    The function expects to be called from ::main(), and should be the
    first database transaction.
*/

Query * Schema::check( EventHandler * owner )
{
    Schema * s = new Schema( owner );

    s->execute();

    return s->d->result;
}


/*! This function is responsible for upgrading the database schema to
    meet the expectations of the running server. When the process is
    complete, the \a owner is notified. The Query returned by this
    function reflects the success or failure of the operation.

    The function expects to be called from ::main().
*/

Query * Schema::upgrade( EventHandler * owner )
{
    // Not just yet.
    return 0;
}
