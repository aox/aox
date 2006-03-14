// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include "global.h"


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

    static void free();
    static void addEternal( void *, const char * );
    static void addEternal( const void * p, const char * c ) {
        addEternal( (void*)p, c );
    }

    static void removeEternal( void * );
    static void removeEternal( const void * );

    static void setReporting( bool );

    static uint allocated();

    static void * alloc( uint, uint = UINT_MAX );
    static void dealloc( void * );

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
    uint * used;
    uint * marked;
    void * buffer;
    Allocator * next;

private:
    static void mark( void * );
    static void mark();
    void sweep();

    static uint scan1( void *, bool = false, uint = 0, uint = UINT_MAX );
    static void scan2( void * );
    static void scanRoots();
};


#endif
