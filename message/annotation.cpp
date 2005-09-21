// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "annotation.h"

#include "allocator.h"
#include "string.h"
#include "query.h"
#include "dict.h"
#include "map.h"
#include "log.h"


static Dict<Annotation> * annotationsByName;
static Map<Annotation> * annotationsById;
static uint largestAnnotationId;


class AnnotationFetcherData
    : public Garbage
{
public:
    AnnotationFetcherData(): o( 0 ), q( 0 ) {}

    EventHandler * o;
    Query * q;
};


/*! \class AnnotationFetcher flag.h

    The AnnotationFetcher class fetches all (or some) annotations from the
    database.
*/


/*! Constructs a AnnotationFetcher which will proceed to do whatever
    is right and good. If \a owner is not null, the AnnotationFetcher
    will notify its \a owner when done.
*/

AnnotationFetcher::AnnotationFetcher( EventHandler * owner )
    : d( new AnnotationFetcherData )
{
    d->o = owner;
    // XXX: the >= in the next line may be an off-by-one. it's
    // harmless, though, since the reader checks whether such a flag
    // exists.
    d->q = new Query( "select id,name from annotation_names "
                      "where id>=$1 order by id",
                      this );
    d->q->bind( 1, ::largestAnnotationId );
    d->q->execute();
    if ( ::annotationsByName )
        return;
    ::annotationsByName = new Dict<Annotation>;
    Allocator::addEternal( ::annotationsByName,
                           "list of existing annotations" );
    ::annotationsById = new Map<Annotation>;
    Allocator::addEternal( ::annotationsById,
                           "list of existing annotations" );
}


class AnnotationData
    : public Garbage
{
public:
    AnnotationData() : id( 0 ) {}
    String name;
    uint id;
};


void AnnotationFetcher::execute()
{
    Row * r = d->q->nextRow();
    while ( r ) {
        String n = r->getString( "name" );
        uint i = r->getInt( "id" );
        // is this the only AnnotationFetcher working now? best to be careful
        Annotation * f = Annotation::find( i );
        if ( !f )
            f = new Annotation( n, i );
        f->d->name = n;
        if ( i > ::largestAnnotationId )
            ::largestAnnotationId = i;
        r = d->q->nextRow();
    }
    if ( !d->q->done() )
        return;

    if ( d->o )
        d->o->execute();
}



/*! \class Annotation flag.h

    The Annotation class represents a single message flag, ie. a named
    binary variable that may be set on any Message.

    A Annotation has a name() and an integer id(), both of which are
    unique. The id is used to store annotations. There is a function to
    find() a specific flag either by name or id, and also one to get a
    list of all known annotations().
*/


/*! Constructs a flag named \a name and with id \a id. Both \a name
    and \a id must be unique.
*/

Annotation::Annotation( const String & name, uint id )
    : d( new AnnotationData )
{
    d->name = name;
    d->id = id;
    if ( !::annotationsByName )
        Annotation::setup();
    ::annotationsByName->insert( name.lower(), this );
    ::annotationsById->insert( id, this );
}


/*! Returns the name of this flag, as specified to the constructor. */

String Annotation::name() const
{
    return d->name;
}


/*! Returns the id of this flag, as specified to the constructor. */

uint Annotation::id() const
{
    return d->id;
}


/*! Returns a pointer to the flag named \a name, or a null pointer of
    there isn't one. The comparison is case insensitive.
*/

Annotation * Annotation::find( const String & name )
{
    if ( !::annotationsByName )
        return 0;
    return ::annotationsByName->find( name.lower() );
}


/*! Returns a pointer to the flag with id \a id, or a null pointer of
    there isn't one.
*/

Annotation * Annotation::find( uint id )
{
    if ( !::annotationsById )
        return 0;
    return ::annotationsById->find( id );
}


/*! Initializes the Annotation subsystem, fetching all known
    annotations from the database.
*/

void Annotation::setup()
{
    (void)new AnnotationFetcher( 0 );
}


class AnnotationCreatorData
    : public Garbage
{
public:
    AnnotationCreatorData(): owner( 0 ) {}
    EventHandler * owner;
    List<Query> queries;
};

/*! \class AnnotationCreator flag.h

    The AnnotationCreator class creates annotations in the database
    and then updates the Annotation index in RAM.

    When created, a AnnotationCreator object immediately sends queries
    to insert the necessary rows, and when that is done, it creates a
    AnnotationFetcher. Only when the AnnotationFetcher is done is the
    owner notified.
*/

/*! Constructs a AnnotationCreator which inserts \a annotations in the
    database and notifies \a owner when the insertion is complete,
    both in RAM and in the database.
*/

AnnotationCreator::AnnotationCreator( EventHandler * owner, const StringList & annotations )
    : d( new AnnotationCreatorData )
{
    d->owner = owner;

    StringList::Iterator it( annotations );
    while ( it ) {
        Query * q 
            = new Query( "insert into annotation_names (name) values ($1)",
                         this );
        q->bind( 1, *it );
        q->execute();
        d->queries.append( q );
        ++it;
    }
}


void AnnotationCreator::execute()
{
    bool done = true;
    List<Query>::Iterator it( d->queries );
    while ( it && done ) {
        if ( !it->done() )
            done = false;
        ++it;
    }
    if ( done )
        (void)new AnnotationFetcher( d->owner );
}
