// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "cache.h"

#include "list.h"
#include "allocator.h"


static List<Cache> * caches;


/*! \class Cache cache.h

    The Cache class is an abstract superclass which allows keeping
    objects in RAM until the next garbage allocation
    (Allocator::free().

    In practice many objects stay around taking up RAM until GC, so we
    might as well use them. For example, if a Message is used several
    times in quick succession, why shouldn't we use the copy that
    actually is there in RAM?

    Subclasses of Cache have to provide cache insertion and
    retrieval. This class provides only one bit of core functionality,
    namely clearing the cache at GC time.
*/


/*! Constructs an empty Cache. This constructor makes sure the object
    will not be freed during garbage collection, and that clear() will
    be called when appropriate.

    \a f is the duration factor of this cache; it will be cleared once
    every \a f garbage collections. It should be low for expensive
    caches and for ones whose objects will stale quickly, large (say
    5-10) for cheap ones whose objects stale slowly.
*/

Cache::Cache( uint f )
    : Garbage(), factor( f ), n( 0 )
{
    if ( !::caches ) {
        ::caches = new List<Cache>;
        Allocator::addEternal( ::caches, "RAM caches" );
    }

    ::caches->append( this );
}


/*! Destroys the cache and ensures that clear() won't be called any
    more.
*/

Cache::~Cache()
{
    if ( ::caches )
        ::caches->remove( this );
}


/*! Calls clear() for each currently extant Cache. Called from
    Allocator::free(). If \a harder is set, then all caches are
    cleared completely, no matter how high their duration factors are.
*/

void Cache::clearAllCaches( bool harder)
{
    List<Cache>::Iterator i( ::caches );
    while ( i ) {
        Cache * c = i;
        ++i;
        c->n++;
        if ( harder || c->n > c->factor ) {
            c->n = 0;
            c->clear(); // careful: no iterator pointing to c meanwhile
        }
    }
}


/*! \fn virtual void Cache::clear() = 0;
    Implemented by subclasses to discards the contents of the cache.
*/
