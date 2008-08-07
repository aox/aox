// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "granter.h"

#include "query.h"
#include "transaction.h"


static struct {
    const char * name;
    bool s, i, u, d;
} privileges[] = {
#include "privileges.inc"
    { 0, false, false, false, false }
};


class GranterData
    : public Garbage
{
public:
    GranterData()
        : state( 0 ), result( 0 ), t( 0 ), q( 0 )
    {}

    int state;
    Query * result;
    String name;
    Transaction * t;
    Query * q;

    StringList rs;
    StringList ri;
    StringList ru;
    StringList rd;
    StringList gs;
    StringList gi;
    StringList gu;
    StringList gd;
};


/*! \class Granter granter.h
    Does the grant work for objects in the database.

    When executed, a Granter object looks at the database to determine
    what privileges the given database user has, revokes anything it
    doesn't need, and grant anything it needs but does not have.
*/

/*! Creates a new Granter to grant permissions to \a name within the
    Transaction \a t on behalf of \a owner, which will be notified
    when the Granter is done. */

Granter::Granter( const String & name, Transaction * t,
                  EventHandler * owner )
    : d( new GranterData )
{
    d->result = new Query( owner );
    d->name = name;
    d->t = t;
}


/*! Returns a pointer to a Query object that can be used to track the
    progress of this Granter. */

Query * Granter::result()
{
    return d->result;
}


void Granter::execute()
{
    if ( d->state == 0 ) {
        String s(
            "select c.relname::text as name, c.relkind::text as kind, "
            "has_table_privilege($1, c.relname, 'select') as can_select, "
            "has_table_privilege($1, c.relname, 'insert') as can_insert, "
            "has_table_privilege($1, c.relname, 'update') as can_update, "
            "has_table_privilege($1, c.relname, 'delete') as can_delete "
            "from pg_class c join pg_namespace n on (c.relnamespace=n.oid) "
            "where c.relkind in ('r','S')"
        );

        d->q = new Query( s, this );
        d->q->bind( 1, d->name );

        String schema( Configuration::text( Configuration::DbSchema ) );
        if ( !schema.isEmpty() ) {
            s.append( " and n.nspname=$2" );
            d->q->bind( 2, schema );
            d->q->setString( s );
        }

        d->state = 1;
        d->t->enqueue( d->q );
        d->t->execute();
    }

    if ( d->state == 1 ) {
        if ( !d->q->done() )
            return;

        if ( d->q->failed() ) {
            d->state = 42;
            d->result->setError( d->q->error() );
            d->result->notify();
            return;
        }

        while ( d->q->hasResults() ) {
            Row * r = d->q->nextRow();
            String name( r->getString( "name" ) );
            String kind( r->getString( "kind" ) );
            bool cs( r->getBoolean( "can_select" ) );
            bool ci( r->getBoolean( "can_insert" ) );
            bool cu( r->getBoolean( "can_update" ) );
            bool cd( r->getBoolean( "can_delete" ) );

            if ( kind == "r" ) {
                uint i = 0;
                while ( privileges[i].name &&
                        name != privileges[i].name )
                    i++;

                if ( privileges[i].name ) {
                    struct {
                        bool has, needs;
                        StringList * revoke;
                        StringList * grant;
                    } l[] = {
                        { cs, privileges[i].s, &d->rs, &d->gs },
                        { ci, privileges[i].i, &d->ri, &d->gi },
                        { cu, privileges[i].u, &d->ru, &d->gu },
                        { cd, privileges[i].d, &d->rd, &d->gd },
                    };

                    uint j = 0;
                    while ( j < 4 ) {
                        bool has = l[j].has;
                        bool needs = l[j].needs;

                        if ( has && !needs )
                            l[j].revoke->append( name );
                        else if ( needs && !has )
                            l[j].grant->append( name );

                        j++;
                    }
                }
            }
            else if ( kind == "S" ) {
                // We always grant select/usage on all sequences.
                // (insert/delete are not supported for sequences.)
                //
                // XXX: has_table_privilege() doesn't support "usage"
                // checks, so we actually grant update, not usage. It
                // is a pity that insert doesn't grant just nextval()
                // rights on a sequence. Besides, 8.1 doesn't support
                // usage rights anyway, so we can't do any better.

                if ( !cs )
                    d->gs.append( name );
                if ( !cu )
                    d->gu.append( name );
            }
        }

        d->state = 2;
    }

    if ( d->state == 2 ) {
        d->q = 0;

        struct {
            const char * op;
            const char * priv;
            StringList * list;
        } pl[] = {
            { "revoke", "select", &d->rs }, { "revoke", "insert", &d->ri },
            { "revoke", "update", &d->ru }, { "revoke", "delete", &d->rd },
            { "grant",  "select", &d->gs }, { "grant",  "insert", &d->gi },
            { "grant",  "update", &d->gu }, { "grant",  "delete", &d->gd }
        };
        uint n = sizeof( pl ) / sizeof( pl[0] );

        uint i = 0;
        while ( i < n ) {
            if ( !pl[i].list->isEmpty() ) {
                String s( pl[i].op );
                s.append( " " );
                s.append( pl[i].priv );
                s.append( " on " );
                s.append( pl[i].list->join( "," ) );
                s.append( *pl[i].op == 'g' ? " to " : " from " );
                s.append( d->name.quoted() );
                d->q = new Query( s, this );
                d->t->enqueue( d->q );
            }
            i++;
        }

        if ( d->q ) {
            d->state = 3;
            d->t->execute();
        }
        else {
            d->state = 4;
            d->result->setState( Query::Completed );
        }
    }

    if ( d->state == 3 ) {
        if ( !d->q->done() )
            return;

        if ( d->t->failed() ) {
            d->state = 42;
            d->result->setError( d->t->error() );
            d->result->notify();
            return;
        }

        d->result->setState( Query::Completed );
        d->state = 4;
    }

    if ( d->state == 4 ) {
        d->state = 42;
        d->result->notify();
    }
}
