// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include "global.h"


extern void * alloc( uint, uint = UINT_MAX );
extern void dealloc( void * );


class Allocator
{
public:
    Allocator( uint );
    ~Allocator();

    void * allocate( uint size, uint pointers );

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
    static void addEternal( void *, const char * );
    static void addEternal( const void * p, const char * c ) {
        addEternal( (void*)p, c );
    }

    static void removeRoot( void * );
    static void removeRoot( const void * );

    static void setReporting( bool );

    static uint allocated();

    uint chunkSize() const;

    static Allocator * owner( void * );
    void deallocate( void * );

    static uint sizeOf( void * );
    static void scan( void * );

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

    static uint scan1( void *, bool = false, uint = 0, uint = UINT_MAX );
    static void scan2( void * );
    static void scanRoots();
};


#endif
