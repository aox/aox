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


void *Garbage::operator new( uint s )
{
    return Allocator::alloc( s );
}


void Garbage::operator delete( void * )
{
    // nothing necessary. and this function isn't called much, either.
}


void *Garbage::operator new[]( uint s )
{
    return Allocator::alloc( s );
}


void Garbage::operator delete[]( void * )
{
    // nothing necessary. and this function isn't called much, either.
}
