// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "allocator.h"

#include "sys.h"
#include "entropy.h"
#include "string.h"
#include "log.h"

// fprintf
#include <stdio.h>


struct AllocationBlock
{
    union {
        struct {
            uint magic: 15;
            uint number: 15;
        } x;
        uint y;
        void * z;
    };
    void* payload[1];
};

const uint SizeLimit = 512 * 1024 * 1024;


static int total;
static uint allocated;
static uint tos;
static uint peak;
static AllocationBlock ** stack;


/*! Allocates \a s bytes of collectible memory, which may contain up
    to \a n pointers. If n is too large to be contained within \a s
    bytes, alloc() uses the largest legal value. The default value is
    UINT_MAX, which in practise means that the entire object may
    consist of pointers.

    Note that \a s is a uint, not a size_t. In our universe, it isn't
    possible to allocate more than 4GB at a time. So it is.
*/


void * Allocator::alloc( uint s, uint n )
{
    if ( s > SizeLimit )
        die( Memory );
    if ( n > s / sizeof( void* ) )
        n = s / sizeof( void* );
    if ( s > 262144 ) {
        fprintf( stderr, "%s", "" );
    }
    Allocator * a = Allocator::allocator( s );
    while ( a->base == a->capacity && a->next )
        a = a->next;
    void * p = a->allocate( s, n );
    if ( ( ( ::total + ::allocated + s ) & 0xfff00000 ) >
         ( ( ::total + ::allocated ) & 0xfff00000 ) )
    {
        // this is a good place to put a breakpoint when we want to
        // find out who allocates memory.
        fprintf( stderr, "%s", "" );
    }
    ::allocated += a->chunkSize();
    return p;
}


/*! Deallocates the object at \a p.

    This is never strictly necessary, however, if a very large number
    of objects are allocated and deallocated, it may be
    beneficial. This function exists because it was beneficial in
    String::reserve().
*/


void Allocator::dealloc( void * p )
{
    Allocator * a = Allocator::owner( p );
    if ( a )
        a->deallocate( p );
}


const uint bytes = sizeof(void*);
const uint bits = 8 * sizeof(void*);
const uint magic = 0x7d34;


static Allocator * allocators[32];
static unsigned long int heapStart;
static unsigned long int heapLength;


static struct {
    void * root;
    const char * name;
    uint size;
} roots[1024];

static uint numRoots;

static const unsigned long int bufferSize = 0x10000;
static Allocator * byStart[bufferSize];

static bool verbose;


/*! Returns a pointer to the Allocator responsible for \a size. \a
    size need not be rounded.
*/

Allocator * Allocator::allocator( uint size )
{
    uint i = 0;
    uint b = 8;
    if ( bits == 64 )
        b = 16;
    while ( size + bytes > b << i )
        i++;
    if ( !allocators[i] ) {
        Allocator * a = new Allocator( b << i );
        allocators[i] = a;
        if ( verbose )
            log( "Allocating " + String::humanNumber( a->capacity * a->step ) +
                 " for " + fn( a->capacity ) + " " +
                 fn( a->step - bytes ) + "-byte objects\n",
                 Log::Debug );
    }
    return allocators[i];
}


/*! \class Allocator allocator.h

    The Allocator class does the heavy lifting for Oryx memory
    allocation system, a simple garbage collector for event-driven
    servers.

    Our GC system is based on the notion of eternal objects and safe
    GC points. Eternal objects must be declared by calling
    addEternal. Collectible objects are allocated by calling alloc(),
    or alternatively by inheriting Garbage. Most Oryx classes inherit
    Garbage.

    The free() function mark all objects that can be reached from the
    eternal ones, and afterwards frees anything which isn't
    reachable. It can be called whenever there are no pointers into
    the heap, ie. only during the main event loop.

    Ech single instance of the Allocator class allocates memory blocks
    of a given size. There are static functions to the heavy loading,
    such as free() to free all unreachable memory, allocate() to
    allocate something, allocator() to find an Allocator responsible
    for a given size and finally rounded(), to find the largest size
    which will fit comfortably in an allocation block, rounded().

    The String and UString classes can call rounded() to optimize
    their memory usage.
*/



/*! This private constructor creates an Allocator to dispense objects
    of size at most \a s - sizeof(void*) bytes.
*/

Allocator::Allocator( uint s )
    : base( 0 ), step( s ), taken( 0 ), capacity( 0 ),
      used( 0 ), marked( 0 ), buffer( 0 ),
      next( 0 )
{
    if ( s < ( 1 << 20 ) )
        capacity = ( 1 << 20 ) / ( s );
    else
        capacity = 1;
    uint l = capacity * s;
    buffer = ::malloc( l );
    uint bl = sizeof( ulong ) * (capacity + bits - 1)/bits;
    used = (ulong*)::malloc( bl );
    marked = (ulong*)::malloc( bl );

    memset( buffer, 0, l );
    memset( used, 0, bl );
    memset( marked, 0, bl );

    ulong hs = (ulong)buffer;
    ulong he = hs + l;
    if ( heapStart ) {
        if ( ::heapStart < hs )
            hs = ::heapStart;
        if ( ::heapStart + ::heapLength > he )
            he = ::heapStart + ::heapLength;
    }
    ::heapStart = hs;
    ::heapLength = he - hs;

    ulong bucket = ((ulong)buffer >> 20)%bufferSize;
    if ( ::byStart[bucket] )
        die( Memory ); // if this happens, we're almost certainly
                       // using MUCH too much memory
    ::byStart[bucket] = this;
}



/*! Destroys the object and frees its allocated memory. Does NOT
    change the heap start/end variables. */

Allocator::~Allocator()
{
    ulong bucket = ((ulong)buffer >> 20)%bufferSize;
    ::byStart[bucket] = 0;

    ::free( buffer );
    ::free( used );
    ::free( marked );

    next = 0;
    used = 0;
    buffer = 0;
}


/*! Allocates a chunk of memory (which may contain up to \a pointers
    pointers), notes that at most \a size bytes are in use, and returns
    a pointer to it.
*/

void * Allocator::allocate( uint size, uint pointers )
{
    if ( taken < capacity ) {
        while ( base < capacity ) {
            ulong bm = used[base/bits];
            if ( bm != ~(0UL) ) {
                uint j = base%bits;
                while ( bm & ( 1UL << j ) )
                    j++;
                base = (base & ~(bits-1)) + j;
                AllocationBlock * b = (AllocationBlock*)block( base );
                if ( b ) {
                    if ( b->x.magic == ::magic ) {
                        if ( verbose )
                            log( "Internal error in allocate" );
                        die( Memory );
                    }
                    b->x.number = pointers;
                    b->x.magic = ::magic;
                    marked[base/bits] &= ~( 1UL << j );
                    used[base/bits] |= ( 1UL << j );
                    taken++;
                    base++;
                    return &(b->payload);
                }
            }
            base = (base | (bits-1)) + 1;
        }
    }

    if ( !next )
        next = new Allocator( step );
    return next->allocate( size, pointers );
}


/*! Deallocates the object at \a p, provided that it's within this
    Allocator. Calling this function is never necessary, since free()
    does the same job. However, String helps out by doing it
    occasionally.
*/

void Allocator::deallocate( void * p )
{
    ulong i = ((ulong)p - (ulong)buffer) / step;
    if ( i >= capacity )
        return;
    if ( ! (used[i/bits] & 1UL << (i%bits)) )
        return;

    AllocationBlock * m = (AllocationBlock *)block( i );
    if ( m->x.magic != ::magic )
        die( Memory );
    used[i/bits] &= ~(1UL << i);
    marked[i/bits] &= ~(1UL << i);
    taken--;
    m->x.magic = 0;

    if ( base > i )
        base = i;
    if ( ::allocated > step )
        ::allocated -= step;
}


/*! Returns a pointer to the Allocator in which \a p lies, or a null
    pointer if \a p doesn't seem to be a valid pointer.
*/

inline Allocator * Allocator::owner( void * p )
{
    if ( !p )
        return 0;
    ulong q = (ulong)p - ::heapStart;
    if ( q >= ::heapLength )
        return 0;
    ulong ai = ((ulong)p >> 20)%bufferSize;
    Allocator * a = 0;
    do {
        a = (Allocator*)(::byStart[ai]);
        ai--;
    } while ( ai && ( !a || (ulong)a->buffer > (ulong)p ) );
    return a;
}


/*! This private helper checks that \a p is a valid pointer to
    unmarked GCable memory, marks it, and puts it on a stack so that
    mark() can process it and add its children to the stack.
*/

void Allocator::mark( void * p )
{
    Allocator * a = owner( p );
    // a is the allocator we may want. does its area encompass p?
    if ( !a || (ulong)a->buffer > (ulong)p )
        return;
    // perhaps, but let's look closer
    ulong i = ((ulong)p - (ulong)a->buffer) / a->step;
    if ( i >= a->capacity )
        return;
    if ( ! (a->used[i/bits] & 1UL << (i%bits)) )
        return;
    // fine. we have the block of memory.
    AllocationBlock * b = (AllocationBlock*)a->block( i );
    // does it have our magic marker?
    if ( b->x.magic != ::magic )
        die( Memory );
    // is it already marked?
    if ( (a->marked[i/bits] & 1UL << (i%bits)) )
        return;
    // no. mark it
    a->marked[i/bits] |= (1UL << (i%bits));
    // is there any chance that it contains children?
    if ( !b->x.number )
        return;
    // is there space on the stack for this object?
    if ( tos == 524288 ) {
        log( "Ran out of stack space while collecting garbage",
             Log::Disaster );
        return;
    }
    // yes. put it on the stack so the children, too, can be marked.
    if ( !stack ) {
        stack = (AllocationBlock**)malloc( 524288 * sizeof(AllocationBlock *) );
        tos = 0;
    }
    stack[tos++] = b;
    if ( tos > peak )
        peak = tos;
}


/*! This private helper processes all the stacked pointers, scanning
    them for valid pointers and marking any that exist.
*/

void Allocator::mark()
{
    while ( tos > 0 ) {
        AllocationBlock * b = stack[--tos];
        // mark its children
        uint n = b->x.number;
        while ( n ) {
            n--;
            if ( b->payload[n] )
                mark( b->payload[n] );
        }
    }
    ::free( stack );
    stack = 0;
    tos = 0;
}


/*! Frees all memory that's no longer in use. This can take some time. */

void Allocator::free()
{
    total = 0;
    uint freed = 0;
    uint objects = 0;
    // mark
    uint i = 0;
    while ( i < ::numRoots ) {
        mark( ::roots[i].root );
        i++;
    }
    mark();
    // and sweep
    i = 0;
    uint blocks = 0;
    while ( i < 32 ) {
        Allocator * a = allocators[i];
        while ( a ) {
            uint taken = a->taken;
            if ( a->taken )
                a->sweep();
            freed = freed + ( taken - a->taken ) * a->step;
            total = total + a->taken * a->step;
            objects += a->taken;
            a = a->next;
        }
        a = allocators[i];
        while ( a ) {
            blocks++;
            while ( a->next && !a->next->taken ) {
                Allocator * n = a->next;
                a->next = a->next->next;
                delete n;
            }
            a = a->next;
        }
        i++;
    }

    dumpRandomObject();

    if ( !freed )
        return;

    if ( verbose && ::allocated >= 524288 )
        log( "Allocator: allocated " +
             String::humanNumber( ::allocated ) +
             " then freed " +
             String::humanNumber( freed ) +
             " bytes, leaving " +
             fn( objects ) +
             " objects of " +
             String::humanNumber( total ) +
             " bytes, across " +
             fn( blocks ) +
             " 1MB blocks. Recursion depth: " +
             fn( peak ) + ".",
             Log::Info );
    if ( verbose && total > 8 * 1024 * 1024 ) {
        String objects;
        i = 0;
        while ( i < 32 ) {
            uint n = 0;
            uint max = 0;
            Allocator * a = allocators[i];
            while ( a ) {
                n = n + a->taken;
                max = max + a->capacity;
                a = a->next;
            }
            if ( n ) {
                if ( objects.isEmpty() )
                    objects = "Objects:";
                else
                    objects.append( "," );
                uint size = allocators[i]->step;
                objects.append( " size " + fn( size-bytes ) + ": " +
                                fn( n ) + " (" +
                                String::humanNumber( size * n ) + " used, " +
                                String::humanNumber( size * max ) +
                                " allocated)" );
            }
            i++;
        }
        log( objects, Log::Info );
    }
    ::allocated = 0;
}


/*! Sweeps this allocator, freeing all unmarked memory blocks and
    unmarking all memory blocks.
*/

void Allocator::sweep()
{
    uint b = 0;
    while ( taken > 0 && b * bits < capacity ) {
        uint i = 0;
        while ( ( used[b] & ~marked[b] ) ) {
            if ( (used[b] & (1UL<<i)) && !(marked[b] & (1UL<<i)) ) {
                AllocationBlock * m
                    = (AllocationBlock *)block( b * bits + i );
                if ( m ) {
                    if ( m->x.magic != ::magic )
                        die( Memory );
                    used[b] &= ~(1UL << i);
                    taken--;
                    m->x.magic = 0;
                    memset( m->payload, 0, step-bytes );
                }
            }
            i++;
        }
        marked[b] = 0;
        b++;
    }
    base = 0;
}


/*! Returns a pointer to block no. \a i in this Allocator. The pointer
    is to the management word, not the payload.
*/

void * Allocator::block( uint i )
{
    if ( i >= capacity )
        return 0;
    return (void *)(i * step + (ulong)buffer);
}


/*! Returns the biggest number of bytes which can be allocated at the
    same effective cost as \a size.

    Suppose allocating 24, 25 or 28 bytes all cause Allocator to use
    32 bytes, but 29 causes Allocator to use 48. Then rounded(24),
    rounded(25) and rounded(28) all return 28, while rounded(29) might
    return something like 44.

    This can be used by String and UString to optimize their memory
    usage. Perhaps also by other classes.
*/

uint Allocator::rounded( uint size )
{
    uint i = 3;
    if ( bits == 64 )
        i = 4;
    while ( 1UL << i < size + bytes )
        i++;
    return (1UL << i) - bytes;
}


/*! Records that \a *p is an allocation root, i.e. that whatever it
    points to is a valid object. \a t is a description of this root
    (e.g. "array of connection objects").
*/

void Allocator::addEternal( const void * p, const char * t )
{
    ::roots[::numRoots].root = (void*)p;
    ::roots[::numRoots].name = t;
    ::roots[::numRoots].size = 0;
    ::numRoots++;
    if ( ::numRoots < 1024 )
        return;

    // we have a nasty memory leak. probably someone's allocating new
    // roots in a loop.
    log( String( "Ran out of roots. Last allocated root: " ) + t,
         Log::Disaster );
    die( Memory );
}


/*! Records that \a *p is no longer an allocation root. The object may
    have been deleted.
*/

void Allocator::removeEternal( void * p )
{
    uint i = 0;
    while( i < ::numRoots && roots[i].root != p )
        i++;
    if ( i >= numRoots )
        return;

    ::numRoots--;
    while( i < ::numRoots ) {
        roots[i].root = roots[i+1].root;
        roots[i].name = roots[i+1].name;
        roots[i].size = 0;
        i++;
    }
}


/*! Records that \a *p is no longer an allocation root. The object may
    have been deleted.
*/

void Allocator::removeEternal( const void * p )
{
    removeEternal( (void*)p );
}


/*! Instructs the Allocator to log various statistics if \a report is
    true, and to be entirely silent if \a report is false.

    The initial value is false.
*/

void Allocator::setReporting( bool report )
{
    ::verbose = report;
}




/*! Returns the number of bytes allocated since the last memory sweep. */

uint Allocator::allocated()
{
    return ::allocated;
}


/*! Returns the number of bytes in use after the last sweep. */

uint Allocator::inUse()
{
    return ::total;
}


/*! Returns the amount of memory gobbled up when this Allocator
    allocates memory. This is a little bigger than the biggest object
    this Allocator can provide.
*/

uint Allocator::chunkSize() const
{
    return step;
}


/*! Scans the pointer in \a p and returns its total size, ie. the sum
    of the sizes of the objects to which it contains. If it contains
    several pointers to the same object, that object is counted several
    times.

    if \a print is true and the total cost is ast least \a limit,
    scan1() also prints some debug output on stdout, prefixed by
    \a level spaces. If \a print is false, \a level and \a limit are
    ignored.
*/

uint Allocator::scan1( void * p, bool print, uint level, uint limit )
{
    uint sz = 0;

    Allocator * a = owner( p );
    if ( !a )
        return 0;

    ulong i = ((ulong)p - (ulong)a->buffer) / a->step;
    AllocationBlock * b = (AllocationBlock *)a->block( i );
    if ( !b )
        return 0;
    if ( ! (a->used[i/bits] & 1 << (i%bits)) )
        return 0;
    if ( (a->marked[i/bits] & 1 << (i%bits)) )
        return 0;
    if ( b->x.magic != ::magic )
        return 0;

    a->marked[i/bits] |= (1 << (i%bits));
    uint n = b->x.number;
    while ( n ) {
        n--;
        if ( b->payload[n] )
            sz += scan1( b->payload[n], print, level+1, limit );
    }
    sz += a->step;

    if ( !print || level >= 5 || (level > 0 && sz < limit ) )
        return sz;

    char s[16];
    if ( sz > 1024*1024*1024 )
        sprintf( s, "%.1fGB", sz / 1024.0 / 1024.0 / 1024.0 );
    else if ( sz > 1024*1024 )
        sprintf( s, "%.1fMB", sz / 1024.0 / 1024.0 );
    else if ( sz > 1024 )
        sprintf( s, "%.1fK", sz / 1024.0 );
    else
        sprintf( s, "%d", sz );
    const char * levelspaces[] = {
        "",
        "    ",
        "        ",
        "            ",
        "                "
    };
    printf( "%s0x%08lx (%s)\n", levelspaces[level], (ulong)p, s );
    return sz;
}


/*! Scans the pointer in \a p and clears all the marked bits left by
    scan1().
*/

void Allocator::scan2( void * p )
{
    Allocator * a = owner( p );
    if ( !a )
        return;

    ulong i = ((ulong)p - (ulong)a->buffer) / a->step;
    AllocationBlock * b = (AllocationBlock *)a->block( i );
    if ( !b )
        return;
    if ( ! (a->used[i/bits] & 1 << (i%bits)) )
        return;
    if ( ! (a->marked[i/bits] & 1 << (i%bits)) )
        return;
    if ( b->x.magic != ::magic )
        return;

    a->marked[i/bits] &= ~(1 << (i%bits));
    uint n = b->x.number;
    while ( n ) {
        n--;
        if ( b->payload[n] )
            scan2( b->payload[n] );
    }
}


/*! This debug function prints a summary of the memory usage for \a p
    on stdout. It can be conveniently be called using 'call
    Allocator::scan( \a p )' from gdb.
*/

void Allocator::scan( void * p )
{
    scan1( p, true, 0, sizeOf( p ) / 20 );
    scan2( p );
}


/*! Returns the amount of memory allocated to hold \a p and any object
    to which p points.

    The return value can bee an overstatement. For example, if \a p
    contains two pointers to the same object, that object is counted
    twice.
*/

uint Allocator::sizeOf( void * p )
{
    uint n = scan1( p, false );
    scan2( p );
    return n;
}


/*! Prints the memory usage of the roots.
*/

void Allocator::scanRoots()
{
    uint n = 0;
    while ( n < numRoots ) {
        if ( roots[n].root )
            fprintf( stdout, "%s(%d) => %d\n", roots[n].name, n,
                     sizeOf( roots[n].root ) );
        n++;
    }
}


/*! This debug function selects an allocated memory block at random
    and dumps its contents to stdout.

    Each allocated byte has the same chance of being chosen, so this
    function has a tendency to pick large objects. (Although, if
    almost all of the allocated objects are 32-byte objects, this
    function is almost certain to pick a 32-byte object.)
*/

void Allocator::dumpRandomObject()
{
    uint r = Entropy::asNumber( 4 );

    // count the number of blocks.
    uint i = 0;
    uint t = 0;
    while ( i < 32 ) {
        Allocator * a = allocators[i];
        while ( a ) {
            t = t + a->taken * a->step;
            a = a->next;
        }
        i++;
    }

    // pick a random byte
    r = r % t;
    
    // find that block
    i = 0;
    t = 0;
    Allocator * a = 0;
    AllocationBlock * b = 0;
    while ( !b && i < 32 ) {
        a = allocators[i];
        while ( a && !b ) {
            if ( t + a->taken * a->step > r ) {
                uint n = 0;
                while ( !b && n < a->capacity ) {
                    if ( a->used[n/bits] & (1UL<<(n%bits)) ) {
                        t += a->step;
                        if ( t > r )
                            b = (AllocationBlock *)a->block( n );
                    }
                    n++;
                }
            }
            if ( !b )
                a = a->next;
        }
        i++;
    }

    if ( !a || !b ) {
        // yes, so dump it as one.
        fprintf( stdout, "Found nothing to dump (%d,%d)\n",
                 r, t );
        return;
    }

    // dump the object: is it a string?
    bool s = true;
    i = 0;
    while ( s && i < 200 && i < a->step-bytes ) {
        char c = ((char*)b->payload)[i];
        if ( c > 126 || ( c < 32 && c != 10 && c != 13 ) )
             s = false;
        i++;
    }
    if ( s ) {
        // yes, so dump it as one.
        fprintf( stdout, "String, maximum length %d, content:\n%s\n",
                 a->step - bytes, (char*)b->payload );
    }
    else {
        // no, so dump it as hex
        fprintf( stdout, "Data, maximum length %d, content:\n",
                 a->step - bytes );
        i = 0;
        bool crlf = false;
        while ( i < 200 && i < a->step-bytes ) {
            crlf = ( i % 16 == 15 );
            fprintf( stdout, "%02x %s",
                     ((char*)b->payload)[i], crlf ? "\n" : "" );
            i++;
        }
        if ( !crlf )
            fprintf( stdout, "%s\n", i < a->step-bytes ? "..." : "" );
    }
}
