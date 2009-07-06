// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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

    static uint rounded( uint size );

    static Allocator * allocator( uint size );

    static void free();
    static void addEternal( const void *, const char * );

    static void removeEternal( void * );
    static void removeEternal( const void * );

    static void setReporting( bool );

    static uint allocated();
    static uint inUse();

    static void * alloc( uint, uint = UINT_MAX );
    static void dealloc( void * );

    uint chunkSize() const;

    static Allocator * owner( const void * );
    void deallocate( void * );

    void setNumPointers( const void *, uint );

    static uint sizeOf( void * );

private:
    typedef unsigned long int ulong;

    uint base;
    uint step;
    uint taken;
    uint capacity;
    ulong * used;
    ulong * marked;
    void * buffer;
    Allocator * next;

    friend void pointers( void * );
    friend class AllocatorMapTable;

private:
    static void mark( void * );
    static void mark();
    void sweep();
};


#endif
