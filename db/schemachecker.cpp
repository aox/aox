// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "schemachecker.h"

#include "transaction.h"
#include "query.h"
#include "log.h"


class SchemaCheckerData
    : public Garbage
{
public:
    SchemaCheckerData():
        Garbage(),
        t( 0 ), tables( 0 ), columns( 0 )
        {}

    Transaction * t;
    Query * tables;
    Query * columns;
};


/*! \class SchemaChecker schemachecker.h

    The SchemaChecker class runs a number of sanity checks against the
    database schema, and notes anything wrong. It uses the pg_* tables
    and a number of automatically generated files based on the current
    Archiveopteryx schema.

    SchemaChecker doesn't report errors; it permits any deviation. It
    just reports differences.
*/



/*! Constructs a SchemaChecker to work using a subtransaction of \a t. */

SchemaChecker::SchemaChecker( Transaction * t )
    : EventHandler(), d( new SchemaCheckerData )
{
    d->t = t->subTransaction( this );
    setLog( new Log );
}


void SchemaChecker::execute()
{
    if ( !d->columns )
        enqueue();
    if ( !d->t->done() )
        return;
    checkColumns();
}


/*! Sends all the queries. */

void SchemaChecker::enqueue()
{
    Query * q = new Query( "create temporary table aoxtables ("
                           "schemaname name, "
                           "tablename name)", 0 );
    d->t->enqueue( q );

    String schemaname;
    String aoxsuper;

    // a list of the tables we ought to have
    if ( schemaname == "public" ) {
        q = new Query( "insert into aoxtables (schemaname, tablename) "
                       "select schemaname, tablename from pg_tables "
                       "where schemaname=$1 and tableowner=$2", 0 );
        q->bind( 1, schemaname );
        q->bind( 2, aoxsuper );
    }
    else {
        q = new Query( "insert into aoxtables (schemaname, tablename) "
                       "select schemanae, tablename from pg_tables "
                       "where schemaname=$1", 0 );
        q->bind( 1, schemaname );
    }
    d->t->enqueue( q );
    d->tables = new Query( "select tablename::text from aoxtables", 0 );
    d->t->enqueue( d->tables );

    // a list of the columns we ought to have
    d->columns = new Query( "select a.attname as column, "
                            "a.attnotnull as notnull, "
                            "pg_catalog.format_type(a.atttypid, a.atttypmod)"
                            " as type, "
                            "c.relname as table, "
                            "n.nspname as namespace "
                            "from pg_attribute a "
                            "join pg_class c on (a.attrelid=c.oid) "
                            "join pg_namespace n on (c.relnamespace=n.oid) "
                            "join aoxtables aox on (c.relname=aox.tablename"
                            " and n.nspname=aox.schemaname) "
                            "where pg_catalog.pg_table_is_visible(c.oid) and "
                            "not a.attisdropped and "
                            "a.attnum>=1",
                            this );
    d->t->enqueue( d->columns );

    // not done: foreign keys
    //
    // this could also check foreign keys in other tables that
    // reference our tables. and foreign keys in our tables that
    // reference others.

    // not done: unique indexes

    // finish off by dropping the table we used and committing
    d->t->enqueue( new Query( "drop table aoxtables", 0 ) );
    d->t->commit();
}


static const struct {
    const char * tablename;
    const char * column;
    const char * type;
    bool notnull;
} expectedColumns[] = {
    { 0, 0, 0, false }
};
     

/*! Checks that the columns we ought to have match those we found in
    the db.
*/

void SchemaChecker::checkColumns()
{
    StringList columnsFound;
    while ( d->columns->hasResults() ) {
        Row * r = d->columns->nextRow();
        String column = r->getString( "column" );
        String table = r->getString( "table" );
        String type = r->getString( "type" );
        bool notnull = r->getBoolean( "notnull" );
        uint i = 0;
        while ( expectedColumns[i].column &&
                ( column != expectedColumns[i].column ||
                  table != expectedColumns[i].tablename ) )
            i++;
        if ( !expectedColumns[i].column ) {
            log( "Did not expect to see column " + column.quoted() +
                 " in table " + table.quoted() );
        }
        else {
            if ( type != expectedColumns[i].type )
                log( "Type mismatch for " + column.quoted() +
                     " in table " + table.quoted() + ": expected " +
                     String( expectedColumns[i].type ).quoted() + ", saw " +
                     type.quoted() );
            if ( notnull && !expectedColumns[i].notnull )
                log( "" + column.quoted() +
                     " in table " + table.quoted() +
                     ": is NOT NULL and should not be" );
            else if ( !notnull && expectedColumns[i].notnull )
                log( "" + column.quoted() +
                     " in table " + table.quoted() +
                     ": should have NOT NULL" );
            columnsFound.append( table + "." + column );
        }
    }
    uint i = 0;
    while ( expectedColumns[i].column ) {
        String x = expectedColumns[i].tablename;
        x.append( "." );
        x.append( expectedColumns[i].column );
        if ( !columnsFound.contains( x ) )
            log( "Could not find column " +
                 String( expectedColumns[i].column ).quoted() +
                 " in table " +
                 String( expectedColumns[i].tablename ).quoted() );
    }
}
