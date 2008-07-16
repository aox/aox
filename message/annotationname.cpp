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
