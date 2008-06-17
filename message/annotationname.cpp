// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "annotationname.h"

#include "configuration.h"
#include "transaction.h"
#include "allocator.h"
#include "dbsignal.h"
#include "string.h"
#include "event.h"
#include "query.h"
#include "dict.h"
#include "map.h"
#include "log.h"


static Dict<uint> * annotationsByName;
static Map<String> * annotationsById;
static uint largestAnnotationNameId;


class AnnotationNameFetcher
    : public EventHandler
{
public:
    AnnotationNameFetcher( EventHandler * o )
        : owner( o ), max( 0 )
    {
        q = new Query( "select id,name from annotation_names "
                       "where id >= $1", this );
        q->bind( 1, ::largestAnnotationNameId );
        q->execute();
    }

    void execute()
    {
        while ( q->hasResults() ) {
            Row * r = q->nextRow();
            uint id = r->getInt( "id" );
            AnnotationName::add( r->getString( "name" ), id );
            if ( id > max )
                max = id;
        }

        if ( !q->done() )
            return;

        ::largestAnnotationNameId = max;

        if ( owner )
            owner->execute();
    }

private:
    EventHandler * owner;
    Query * q;
    uint max;
};


class AnnotationNameCreator
    : public EventHandler
{
public:
    StringList names;
    Transaction * t;
    int state;
    Query * q;
    Query * result;
    Dict<uint> unided;
    int savepoint;

    AnnotationNameCreator( const StringList & f, Transaction * tr,
                           EventHandler * ev )
        : names( f ), t( tr ), state( 0 ), q( 0 ), savepoint( 0 )
    {
        result = new Query( ev );
        execute();
    }

    void execute();
    void selectAnnotations();
    void processAnnotations();
    void insertAnnotations();
    void processInsert();
};

void AnnotationNameCreator::execute()
{
    if ( state == 0 )
        selectAnnotations();

    if ( state == 1 )
        processAnnotations();

    if ( state == 2 )
        insertAnnotations();

    if ( state == 3 )
        processInsert();

    if ( state == 4 ) {
        state = 42;
        if ( !result->done() )
            result->setState( Query::Completed );
        result->notify();
    }
}

void AnnotationNameCreator::selectAnnotations()
{
    q = new Query( "select id, name from annotation_names where "
                   "name=any($1)", this );

    unided.clear();

    StringList sl;
    StringList::Iterator it( names );
    while ( it ) {
        String name( *it );
        if ( AnnotationName::id( name ) == 0 ) {
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

void AnnotationNameCreator::processAnnotations()
{
    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        uint id = r->getInt( "id" );
        String name( r->getString( "name" ) );
        AnnotationName::add( name, id );
        unided.take( name );
    }

    if ( !q->done() )
        return;

    if ( unided.isEmpty() ) {
        state = 0;
        selectAnnotations();
    }
    else {
        state = 2;
    }
}

void AnnotationNameCreator::insertAnnotations()
{
    q = new Query( "savepoint d" + fn( savepoint ), this );
    t->enqueue( q );

    q = new Query( "copy annotation_names (name) "
                   "from stdin with binary", this );
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

void AnnotationNameCreator::processInsert()
{
    if ( !q->done() )
        return;

    state = 0;
    if ( q->failed() ) {
        if ( q->error().contains( "annotation_names_name_key" ) ) {
            q = new Query( "rollback to d" + fn( savepoint ), this );
            t->enqueue( q );
            savepoint++;
        }
        else {
            result->setState( Query::Failed );
            state = 4;
        }
    }
    else {
        q = new Query( "release savepoint d" + fn( savepoint ), this );
        t->enqueue( q );
    }

    if ( state == 0 )
        selectAnnotations();
}


class AnnotationNameObliterator
    : public EventHandler
{
public:
    AnnotationNameObliterator(): EventHandler() {
        setLog( new Log( Log::Server ) );
        (void)new DatabaseSignal( "obliterated", this );
    }
    void execute() {
        AnnotationName::reload();
    }
};


/*! \class AnnotationName annotationname.h
    Maps annotation entry names to ids using the annotation_names table.

    The annotation_names table contains an (id,name) map for all known
    annotations, and the annotations table refers to it by id. This
    class provides lookup functions by id and name.
*/


/*! This function must be called once from main() to set up and load
    the flag_names table. */

void AnnotationName::setup()
{
    ::annotationsByName = new Dict<uint>;
    Allocator::addEternal( ::annotationsByName,
                           "list of annotations by name" );

    ::annotationsById = new Map<String>;
    Allocator::addEternal( ::annotationsById, "list of annotations by id" );

    if ( !Configuration::toggle( Configuration::Security ) )
        (void)new AnnotationNameObliterator;

    reload();
}


/*! This function reloads the annotation_names table and notifies the
    \a owner when that is finished. */

void AnnotationName::reload( EventHandler * owner )
{
    ::largestAnnotationNameId = 0;
    ::annotationsById->clear();
    ::annotationsByName->clear();

    (void)new AnnotationNameFetcher( owner );
}


/*! Discards any annotation names that have been created by calling
    add() rather than being loaded from the database. */

void AnnotationName::rollback()
{
    if ( !::annotationsById )
        return;

    StringList::Iterator it( ::annotationsByName->keys() );
    while ( it ) {
        String k( *it );
        uint id = *::annotationsByName->find( k );
        if ( id > largestAnnotationNameId ) {
            ::annotationsByName->take( k );
            ::annotationsById->remove( id );
        }
        ++it;
    }
}


/*! Returns the largest known id for an annotation name. May be 0 if the
    annotation_names table has not yet been loaded. */

uint AnnotationName::largestId()
{
    return ::largestAnnotationNameId;
}


/*! Issues the queries needed to create the specified annotation
    \a names in the transaction \a t and notifies the \a owner when that
    is done, i.e. when id() and name() recognise the newly-created
    annotation names.
*/

Query * AnnotationName::create( const StringList & names,
                                Transaction * t, EventHandler * owner )
{
    return (new AnnotationNameCreator( names, t, owner ))->result;
}


/*! Records that an annotation entry with the given \a name and \a id
    exists. After this call, id( \a name ) returns \a id, and
    name( \a id ) returns \a name. */

void AnnotationName::add( const String & name, uint id )
{
    String * n = new String( name );
    n->detach();

    ::annotationsById->insert( id, n );

    uint * tmp = (uint *)Allocator::alloc( sizeof(uint), 0 );
    *tmp = id;

    ::annotationsByName->insert( name, tmp );
}


/*! Returns the id of the annotation entry with the given \a name, or 0
    if the entry is not known. */

uint AnnotationName::id( const String & name )
{
    uint id = 0;

    if ( ::annotationsByName ) {
        uint * p = ::annotationsByName->find( name );
        if ( p )
            id = *p;
    }

    return id;
}


/*! Returns the annotation entry name with the given \a id, or an empty
    string if the name is not known. */

String AnnotationName::name( uint id )
{
    String name;

    if ( ::annotationsById ) {
        String * p = ::annotationsById->find( id );
        if ( p )
            name = *p;
    }

    return name;
}
