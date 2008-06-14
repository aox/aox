// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "fieldname.h"

#include "allocator.h"
#include "dbsignal.h"
#include "string.h"
#include "event.h"
#include "query.h"
#include "dict.h"
#include "map.h"
#include "log.h"


static Dict<uint> * fieldsByName;
static Map<String> * fieldsById;
static uint largestFieldNameId;


class FieldNameFetcher
    : public EventHandler
{
public:
    FieldNameFetcher( EventHandler * o )
        : owner( o ), max( 0 )
    {
        q = new Query( "select id,name from field_names "
                       "where id >= $1", this );
        q->bind( 1, ::largestFieldNameId );
        q->execute();
    }

    void execute()
    {
        while ( q->hasResults() ) {
            Row * r = q->nextRow();
            uint id = r->getInt( "id" );
            FieldName::add( r->getString( "name" ), id );
            if ( id > max )
                max = id;
        }

        if ( !q->done() )
            return;

        ::largestFieldNameId = max;

        if ( owner )
            owner->execute();
    }

private:
    EventHandler * owner;
    Query * q;
    uint max;
};


class FieldNameCreator
    : public EventHandler
{
public:
    FieldNameCreator( const StringList & fields, EventHandler * o )
        : owner( o )
    {
        StringList::Iterator it( fields );
        while ( it ) {
            Query * q =
                new Query( "insert into field_names (name) values ($1)",
                           this );
            q->bind( 1, *it );
            q->allowFailure();
            q->execute();
            queries.append( q );
            ++it;
        }
    }

    void execute()
    {
        List<Query>::Iterator it( queries );
        while ( it ) {
            if ( it->done() )
                queries.take( it );
            else
                ++it;
        }

        if ( queries.isEmpty() )
            (void)new FieldNameFetcher( owner );
    }

private:
    EventHandler * owner;
    List<Query> queries;
};


class FieldNameObliterator
    : public EventHandler
{
public:
    FieldNameObliterator(): EventHandler() {
        setLog( new Log( Log::Server ) );
        (void)new DatabaseSignal( "obliterated", this );
    }
    void execute() {
        FieldName::reload();
    }
};


/*! \class FieldName fieldname.h
    Maps RFC 822 field names to ids using the field_names table.

    The field_names table contains an (id,name) map for all known header
    field names, and other tables like header_fields refer to it by id.
    This class provides lookup functions by id and name.
*/


/*! This function must be called once from main() to set up and load
    the field_names table. */

void FieldName::setup()
{
    ::fieldsByName = new Dict<uint>;
    Allocator::addEternal( ::fieldsByName, "list of fields by name" );

    ::fieldsById = new Map<String>;
    Allocator::addEternal( ::fieldsById, "list of fields by id" );

    reload();
}


/*! This function reloads the field_names table and notifies the
    \a owner when that is finished. */

void FieldName::reload( EventHandler * owner )
{
    ::largestFieldNameId = 0;
    ::fieldsById->clear();
    ::fieldsByName->clear();

    (void)new FieldNameFetcher( owner );
}


/*! Creates the specified \a fields and notifies the \a owner when that
    is finished, i.e. when id() and name() recognise the newly-created
    field names. */

void FieldName::create( const StringList & fields, EventHandler * owner )
{
    (void)new FieldNameCreator( fields, owner );
}


/*! Records that a field with the given \a name and \a id exists. After
    this call, id( \a name ) returns \a id, and name( \a id ) returns
    \a name. */

void FieldName::add( const String & name, uint id )
{
    String * n = new String( name );
    n->detach();

    ::fieldsById->insert( id, n );

    uint * tmp = (uint *)Allocator::alloc( sizeof(uint), 0 );
    *tmp = id;

    ::fieldsByName->insert( name.lower(), tmp );
}


/*! Returns the id of the field with the given \a name, or 0 if the
    field is not known. */

uint FieldName::id( const String & name )
{
    uint id = 0;

    if ( ::fieldsByName ) {
        uint * p = ::fieldsByName->find( name.lower() );
        if ( p )
            id = *p;
    }

    return id;
}


/*! Returns the name of the field with the given \a id, or an empty
    string if the field is not known. */

String FieldName::name( uint id )
{
    String name;

    if ( ::fieldsById ) {
        String * p = ::fieldsById->find( id );
        if ( p )
            name = *p;
    }

    return name;
}
