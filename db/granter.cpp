// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
        : t( 0 ), q( 0 )
    {}

    EString name;
    Transaction * t;
    Query * q;
};


/*! \class Granter granter.h
    Does the grant work for objects in the database.

    When executed, a Granter object looks at the database to determine
    what privileges the given database user has, revokes anything it
    doesn't need, and grant anything it needs but does not have.
*/

/*! Creates a new Granter to grant permissions to \a name within the
    Transaction \a t. The transactions's owner will be notified
    when the Granter is done. */

Granter::Granter( const EString & name, Transaction * t )
    : d( new GranterData )
{
    d->name = name;
    d->t = t->subTransaction( this );
}


void Granter::execute()
{
    if ( !d->q ) {
        d->q = new Query(
            "select c.relname::text as name, c.relkind::text as kind, "
            "has_table_privilege($1, c.relname, 'select') as can_select, "
            "has_table_privilege($1, c.relname, 'insert') as can_insert, "
            "has_table_privilege($1, c.relname, 'update') as can_update, "
            "has_table_privilege($1, c.relname, 'delete') as can_delete "
            "from pg_class c join pg_namespace n on (c.relnamespace=n.oid) "
            "where c.relkind in ('r','S') and n.nspname=$2 order by name",
            this );
        d->q->bind( 1, d->name );
        d->q->bind( 2, Configuration::text( Configuration::DbSchema ) );
        d->t->enqueue( d->q );
        d->t->execute();
    }

    while ( d->q->hasResults() ) {
        Row * r = d->q->nextRow();
        EString name( r->getEString( "name" ) );
        EString kind( r->getEString( "kind" ) );
        bool cs = r->getBoolean( "can_select" );
        bool ci = r->getBoolean( "can_insert" );
        bool cu = r->getBoolean( "can_update" );
        bool cd = r->getBoolean( "can_delete" );
        EStringList grant;
        EStringList revoke;

        if ( kind == "r" ) {
            uint i = 0;
            while ( privileges[i].name &&
                    name != privileges[i].name )
                i++;

            if ( privileges[i].name ) {
                if ( privileges[i].s && !cs )
                    grant.append( "select" );
                if ( privileges[i].i && !ci )
                    grant.append( "insert" );
                if ( privileges[i].u && !cu )
                    grant.append( "update" );
                if ( privileges[i].d && !cd )
                    grant.append( "delete" );

                if ( !privileges[i].s && cs )
                    revoke.append( "select" );
                if ( !privileges[i].i && ci )
                    revoke.append( "insert" );
                if ( !privileges[i].u && cu )
                    revoke.append( "update" );
                if ( !privileges[i].d && cd )
                    revoke.append( "delete" );
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
                grant.append( "select" );
            if ( !cu )
                grant.append( "update" );
        }

        if ( !grant.isEmpty() )
            d->t->enqueue( new Query( "grant " + grant.join( ", " ) +
                                      " on " + name +
                                      " to " + d->name.quoted(), 0 ) );
        if ( !revoke.isEmpty() )
            d->t->enqueue( new Query( "revoke " + revoke.join( ", " ) +
                                      " on " + name +
                                      " from " + d->name.quoted(), 0 ) );
    }
    if ( !d->q->done() )
        return;

    d->t->commit();
}
