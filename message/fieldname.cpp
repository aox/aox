// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "fieldname.h"

#include "transaction.h"
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
    StringList fields;
    Transaction * t;
    int state;
    Query * q;
    Query * result;
    Dict<uint> unided;
    int savepoint;

    FieldNameCreator( const StringList & f, Transaction * tr,
                      EventHandler * ev )
        : fields( f ), t( tr ),
          state( 0 ), q( 0 ), savepoint( 0 )
    {
        result = new Query( ev );
        execute();
    }

    void execute();
    void selectFields();
    void processFields();
    void insertFields();
    void processInsert();
};

void FieldNameCreator::execute()
{
    if ( state == 0 )
        selectFields();

    if ( state == 1 )
        processFields();

    if ( state == 2 )
        insertFields();

    if ( state == 3 )
        processInsert();

    if ( state == 4 ) {
        state = 42;
        if ( !result->done() )
            result->setState( Query::Completed );
        result->notify();
    }
}

void FieldNameCreator::selectFields()
{
    q = new Query( "select id, name from field_names where "
                   "name=any($1)", this );

    unided.clear();

    StringList sl;
    StringList::Iterator it( fields );
    while ( it ) {
        String name( *it );
        if ( FieldName::id( name ) == 0 ) {
            sl.append( name );
            unided.insert( name, 0 );
        }
        ++it;
    }
    q->bind( 1, sl );
    q->allowSlowness();

    if ( sl.isEmpty() ) {
        state = 4;
    }
    else {
        state = 1;
        t->enqueue( q );
        t->execute();
    }
}

void FieldNameCreator::processFields()
{
    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        uint id( r->getInt( "id" ) );
        String name( r->getString( "name" ) );
        FieldName::add( name, id );
        unided.take( name );
    }

    if ( !q->done() )
        return;

    if ( unided.isEmpty() ) {
        state = 0;
        selectFields();
    }
    else {
        state = 2;
    }
}

void FieldNameCreator::insertFields()
{
    q = new Query( "savepoint e" + fn( savepoint ), this );
    t->enqueue( q );

    q = new Query( "copy field_names (name) from stdin with binary", this );
    StringList::Iterator it( unided.keys() );
    while ( it ) {
        q->bind( 1, *it );
        q->submitLine();
        ++it;
    }

    state = 3;
    t->enqueue( q );
    t->execute();
}

void FieldNameCreator::processInsert()
{
    if ( !q->done() )
        return;

    state = 0;
    if ( q->failed() ) {
        if ( q->error().contains( "field_names_name_key" ) ) {
            q = new Query( "rollback to e" + fn( savepoint ), this );
            t->enqueue( q );
            savepoint++;
        }
        else {
            result->setState( Query::Failed );
            state = 4;
        }
    }
    else {
        q = new Query( "release savepoint e" + fn( savepoint ), this );
        t->enqueue( q );
    }

    if ( state == 0 )
        selectFields();
}


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


/*! Discards any field names that have been created by calling add()
    rather than being loaded from the database. */

void FieldName::rollback()
{
    if ( !::fieldsById )
        return;

    StringList::Iterator it( ::fieldsByName->keys() );
    while ( it ) {
        String k( *it );
        uint id = *::fieldsByName->find( k );
        if ( id > largestFieldNameId ) {
            ::fieldsByName->take( k );
            ::fieldsById->remove( id );
        }
        ++it;
    }
}


/*! Issues the queries needed to create the specified \a fields in the
    transaction \a t, and notifies the \a owner when that is done, i.e.
    when when id() and name() recognise the newly-created field names.
*/

Query * FieldName::create( const StringList & fields, Transaction * t,
                           EventHandler * owner )
{
    return (new FieldNameCreator( fields, t, owner ))->result;
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

    ::fieldsByName->insert( name, tmp );
}


/*! Returns the id of the field with the given \a name, or 0 if the
    field is not known. */

uint FieldName::id( const String & name )
{
    uint id = 0;

    if ( ::fieldsByName ) {
        uint * p = ::fieldsByName->find( name );
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
