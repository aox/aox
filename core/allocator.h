// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include "global.h"


extern void * alloc( uint );


class Allocator
{
public:
    Allocator( uint );
    ~Allocator();

    void * allocate( uint size );

    void * block( uint );

    static uint rounded( uint size ) {
        uint i = 0;
        while ( 8U << i < size + 4 )
            i++;
        return (8U << i) - 4U;
    }

    static Allocator * allocator( uint size );

    void *operator new( uint );
    void operator delete( void * );

    static void free();
    static void addRoot( void * );
    static void addRoot( const void * );
    static void removeRoot( void * );
    static void removeRoot( const void * );

    static void setReporting( bool );
    
private:
    uint base;
    uint step;
    uint taken;
    uint capacity;
    uint * bitmap;
    void * buffer;
    Allocator * next;

private:
    static void mark( void * );
    void sweep();
};


#endif
