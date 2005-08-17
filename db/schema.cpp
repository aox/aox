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
          state( 0 ), substate( 0 ), revision( 0 ),
          lock( 0 ), seq( 0 ), update( 0 ), q( 0 ), t( 0 ),
          result( 0 ), upgrade( false )
    {}

    Log *l;
    int state;
    int substate;
    int revision;
    Query *lock, *seq, *update, *q;
    Transaction *t;
    Query *result;
    bool upgrade;
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
        d->lock =
            new Query( "select revision from mailstore for update", this );
        d->t->enqueue( d->lock );
        d->t->execute();
        d->state = 1;
    }

    if ( d->state == 1 ) {
        if ( !d->lock->done() )
            return;

        Row *r = d->lock->nextRow();
        if ( r )
            d->revision = r->getInt( "revision" );

        if ( !r || d->lock->failed() ) {
            d->l->log( "Bad database: Couldn't query the mailstore table.",
                       Log::Disaster );
            d->result->setState( Query::Failed );
            d->revision = currentRevision;
            d->t->commit();
            d->state = 7;
        }
        else if ( d->revision == currentRevision ) {
            d->result->setState( Query::Completed );
            d->t->commit();
            d->state = 7;
        }
        else if ( d->upgrade && d->revision < currentRevision ) {
            d->l->log( "Updating schema from revision " +
                       fn( d->revision ) + " to revision " +
                       fn( currentRevision ) );
            d->state = 2;
        }
        else {
            String s( "The existing schema (revision #" );
            s.append( fn( d->revision ) );
            s.append( ") is " );
            if ( d->revision < currentRevision )
                s.append( "older" );
            else
                s.append( "newer" );
            s.append( " than this server (version " );
            s.append( Configuration::compiledIn( Configuration::Version ) );
            s.append( ") expected (revision #" );
            s.append( fn( currentRevision ) );
            s.append( "). Please " );
            if ( d->revision < currentRevision )
                s.append( "run 'ms migrate'" );
            else
                s.append( "upgrade" );
            s.append( " or contact support." );
            d->l->log( s, Log::Disaster );
            d->result->setState( Query::Failed );
            d->revision = currentRevision;
            d->t->commit();
            d->state = 7;
        }
    }

    while ( d->revision < currentRevision ) {
        if ( d->state == 2 ) {
            d->seq =
                new Query( "select nextval('revisions')::integer as seq",
                           this );
            d->t->enqueue( d->seq );
            d->t->execute();
            d->state = 3;
        }

        if ( d->state == 3 ) {
            if ( !d->seq->done() )
                return;

            int gap = d->seq->nextRow()->getInt( "seq" ) - d->revision;
            if ( gap > 1 ) {
                d->l->log( "Can't upgrade schema because an earlier "
                           "attempt to do so failed.", Log::Disaster );
                d->result->setState( Query::Failed );
                d->revision = currentRevision;
                d->t->commit();
                d->state = 7;
                break;
            }
            d->state = 4;
        }

        if ( d->state == 4 ) {
            // ...
        }

        if ( d->state == 5 ) {
            d->update =
                new Query( "update mailstore set revision=revision+1",
                           this );
            d->t->enqueue( d->update );
            d->t->execute();
            d->state = 6;
        }

        if ( d->state == 6 ) {
            if ( !d->update->done() )
                return;

            d->state = 2;
            d->revision++;

            if ( d->revision == currentRevision ) {
                d->t->commit();
                d->state = 8;
                break;
            }
        }
    }

    if ( d->state == 7 || d->state == 8 ) {
        if ( !d->t->done() )
            return;

        if ( d->t->failed() && !d->result->failed() ) {
            d->result->setState( Query::Failed );
            d->l->log( "The schema transaction failed.", Log::Disaster );
        }
        else if ( d->state == 8 ) {
            d->result->setState( Query::Completed );
            d->l->log( "Schema updated to revision " +fn( currentRevision ) );
        }
        d->state = 9;
    }

    if ( d->state == 9 ) {
        d->state = 42;
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
    Schema * s = new Schema( owner );
    s->d->upgrade = true;
    s->execute();

    return s->d->result;
}
