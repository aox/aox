// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "global.h"

#include "allocator.h"
#include "log.h"


// This is just to aid in debugging.
void die( Exception e )
{
    switch ( e ) {
    case Invariant:
        log( "die( Invariant ) called", Log::Error );
        break;
    case Memory:
        // we log nothing in this case - Allocator can call this
        break;
    case FD:
        log( "die( FD ) called", Log::Error );
        break;
    }
    throw e;
}


/*! \class Garbage global.h

    The Garbage class provides an object which will allocated using
    Allocator and be freed automatically when nothing points to it.

    Almost all Oryx classes inherit Garbage directly or
    indirectly. Any that need special allocation handling (Allocator
    itself is one example) can avoid inheriting Garbage, or can
    provide their own operator new implementations which call
    ::malloc() or the Allocator's ::alloc() on their own.
*/


/*! \fn Garbage::Garbage()

    Creates garbage to justify garbage collection.
*/


void *Garbage::operator new( size_t s )
{
    return Allocator::alloc( (uint)s );
}


void Garbage::operator delete( void * )
{
    // nothing necessary. and this function isn't called much, either.
}


void *Garbage::operator new[]( size_t s )
{
    return Allocator::alloc( (uint)s );
}


void Garbage::operator delete[]( void * )
{
    // nothing necessary. and this function isn't called much, either.
}


/*! Informs the Allocator to consider that this object contains no
    pointers at or after \a p. This makes Allocator::free() faster and
    more accurate.
*/

void Garbage::setFirstNonPointer( const void * p ) const
{
    unsigned long int t = (unsigned long int)this;
    unsigned long int o = (unsigned long int)p;
    Allocator * a = Allocator::owner( this );
    a->setNumPointers( this, ( o + sizeof(void*)-1 - t ) / sizeof(void*) );
}
