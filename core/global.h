// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef GLOBAL_H
#define GLOBAL_H

#include <stddef.h>

#if !defined(U32_MAX)
#define U32_MAX (0xffffffffU)
#endif

#if !defined(UINT_MAX)
#define UINT_MAX ((uint)~0)
#endif

#if !defined(INT_MAX)
#define INT_MAX 0x7fffffff
#endif

typedef short int int16;
typedef unsigned int uint;
typedef unsigned int uint32;
typedef unsigned short ushort;

enum Exception {
    Range,
    Memory,
    FD
};

void die( Exception );


class Garbage
{
public:
    Garbage() {}

    void *operator new( size_t );
    void *operator new[]( size_t );
    void operator delete( void * );
    void operator delete[]( void * );

};

#endif
