// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "fieldcache.h"

#include "allocator.h"
#include "event.h"
#include "query.h"
#include "dict.h"
#include "list.h"
#include "map.h"


static Map< String > *idCache;
static Dict< uint > *nameCache;
static PreparedStatement *fieldLookup;
static PreparedStatement *fieldInsert;


/*! \class FieldNameCache fieldcache.h
    This class maintains a cache of the field_names table.

    This class is responsible for finding the numeric id corresponding
    to the name of a header field in the field_names table. It may use
    its in-memory cache to find the id, SELECT a row from field_names,
    or, failing that, INSERT a new row and retrieve its id.

    (...We want to describe id lookups here...)

    This class is used only by the Injector at present.
*/

/*! This function initialises the cache of field names at startup.
    It expects to be called from ::main().
*/

void FieldNameCache::setup()
{
    idCache = new Map< String >;
    nameCache = new Dict< uint >;

    fieldLookup =
        new PreparedStatement( "select id from field_names where name=$1" );

    fieldInsert =
        new PreparedStatement( "insert into field_names (name) values ($1)" );

    Allocator::addRoot( idCache );
    Allocator::addRoot( nameCache );
    Allocator::addRoot( fieldLookup );
    Allocator::addRoot( fieldInsert );
}


class FieldLookup
    : public EventHandler
{
protected:
    Query *q;
    String field;
    CacheLookup *status;
    EventHandler *owner;
    List< Query > *queries;

public:
    FieldLookup() {}
    virtual ~FieldLookup() {}

    FieldLookup( const String &f, List< Query > *l, CacheLookup *st,
                       EventHandler *ev )
        : field( f ), status( st ), owner( ev ), queries( l )
    {
        q = new Query( *fieldLookup, this );
        q->bind( 1, field );
        l->append( q );
    }

    void execute();
};


class FieldInsert
    : public FieldLookup
{
public:
    FieldInsert( const String &f, List< Query > *l, CacheLookup *st,
                       EventHandler *ev )
    {
        field = f;
        status = st;
        owner = ev;
        queries = l;

        Query *i = new Query( *fieldInsert, this );
        i->bind( 1, field );

        q = new Query( *fieldLookup, this );
        q->bind( 1, field );
        l->append( q );

        Database *db = Database::handle();
        db->enqueue( i );
        db->enqueue( q );
        db->execute();
    }
};


void FieldLookup::execute() {
    if ( !q->done() )
        return;

    Row *r = q->nextRow();
    delete queries->take( queries->find( q ) );

    if ( !r ) {
        // It may be better to collect INSERTs and execute them together
        // on one database handle after processing the SELECTs. We don't
        // bother yet.
        (void)new FieldInsert( field, queries, status, owner );
        return;
    }

    uint id = r->getInt( "id" );
    String *name = new String( field );
    idCache->insert( id, name );
    nameCache->insert( *name, new uint( id ) );

    if ( queries->isEmpty() ) {
        status->setState( CacheLookup::Completed );
        owner->execute();
    }
}


/*! This function takes a List \a l of field names, and notifies \a ev
    after it has updated its cache for each field therein. The caller
    may then use translate() to retrieve the id.
*/

CacheLookup *FieldNameCache::lookup( List< String > *l, EventHandler *ev )
{
    CacheLookup *status = new CacheLookup;
    List< Query > *lookups = new List< Query >;

    List< String >::Iterator it( l->first() );
    while ( it ) {
        String field = *it++;

        if ( nameCache->find( field ) == 0 )
            (void)new FieldLookup( field, lookups, status, ev );
    }

    if ( lookups->isEmpty() )
        status->setState( CacheLookup::Completed );
    else
        Database::query( lookups );

    return status;
}


/*! This static function returns the numeric id corresponding to the
    specified \a field name.
*/

HeaderField::Type FieldNameCache::translate( const String &field )
{
    return *(HeaderField::Type *)nameCache->find( field );
}
