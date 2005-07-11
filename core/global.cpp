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
*/


void *Garbage::operator new( uint s )
{
    return ::alloc( s, s/sizeof( void* ) );
}


void Garbage::operator delete( void * )
{
    // nothing necessary. and this function isn't called much, either.
}


void *Garbage::operator new[]( uint s )
{
    return ::alloc( s, s/sizeof( void* ) );
}


void Garbage::operator delete[]( void * )
{
    // nothing necessary. and this function isn't called much, either.
}
