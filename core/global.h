#ifndef GLOBAL_H
#define GLOBAL_H

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

void *alloc( uint );

#endif
