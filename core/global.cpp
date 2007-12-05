// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "global.h"

#include "allocator.h"


// This is just to aid in debugging.
void die( Exception e )
{
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
    ulong t = (ulong)this;
    ulong o = (ulong)p;
    Allocator * a = Allocator::owner( this );
    a->setNumPointers( this, ( o + sizeof(void*)-1 - t ) / sizeof(void*) );
}
