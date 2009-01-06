// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "allocator.h"

#include "sys.h"
#include "cache.h"
#include "string.h"
#include "log.h"

// typeid
#include <typeinfo>

// fprintf
#include <stdio.h>

// timeval, gettimeofday
#include <sys/time.h>
#include <time.h>

// mmap, munmap
#include <sys/mman.h>

#include <errno.h>



//#define ARNT


struct AllocationBlock
{
    union {
        struct {
            uint magic: 15;
            uint number: 7;
        } x;
        uint y;
        void * z;
#if defined(ARNT)
        AllocationBlock * up;
#endif
    };
    void* payload[0];
};

const uint SizeLimit = 512 * 1024 * 1024;


static int total;
static uint allocated;
static uint objects;
static uint marked;
static uint tos;
static uint peak;
static AllocationBlock ** stack;

static Allocator * root = 0;


static void oneMegabyteAllocated()
{
    // this is a good place to put a breakpoint when we want to
    // find out who allocates memory.
}


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
        ::oneMegabyteAllocated();
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


const uint bytes = sizeof(AllocationBlock);
const uint bits = 8 * sizeof(void*);
const uint magic = 0x7d34;


static Allocator * allocators[32];


static struct {
    void * root;
    const char * name;
    uint objects;
    uint size;
} roots[1024];

static uint numRoots;

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
                 " for " + fn( a->capacity ) + " " + fn( a->step - bytes ) +
                 "-byte objects", Log::Debug );
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
      next( 0 ), left( 0 ), right( 0 )
{
    if ( s < ( 1 << 20 ) )
        capacity = ( 1 << 20 ) / ( s );
    else
        capacity = 1;
    uint l = capacity * s;
    l = ( ( l-1 ) | 15 ) + 1;
    uint bl = sizeof( ulong ) * ((capacity + bits - 1)/bits);
    bl = ( ( bl-1 ) | 15 ) + 1;
#if defined( MAP_ANON )
    buffer = ::mmap( 0, l + bl + bl,
                     PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0 );
    if ( buffer == MAP_FAILED )
        die( Memory );
    used = (ulong*)((char*)buffer + l);
    marked = (ulong*)((char*)used + bl);
#else
    buffer = ::malloc( l );
    used = (ulong*)::malloc( bl );
    marked = (ulong*)::malloc( bl );
    if ( !buffer || !used || !marked )
        die( Memory );
#endif

    memset( buffer, 0, l );
    memset( used, 0, bl );
    memset( marked, 0, bl );

    insert();
}



/*! Destroys the object and frees its allocated memory. */

Allocator::~Allocator()
{
    if ( ::root == this ) {
        ::root = 0;
    }
    else {
        Allocator * p = ::root;
        Allocator * prev = 0;
        while ( p != prev ) {
            prev = p;
            if ( p->right == this )
                p->right = 0;
            else if ( p->left == this )
                p->left = 0;
            else if ( (ulong)p->buffer < (ulong)buffer )
                p = p->right;
            else if ( (ulong)p->buffer > (ulong)buffer )
                p = p->left;
        }
    }
    if ( right && right != ::root )
        right->insert();
    if ( left && left != ::root )
        left->insert();

    right = 0;
    left = 0;

#if defined( MAP_ANON )
    uint l = capacity * step;
    l = ( ( l-1 ) | 15 ) + 1;
    uint bl = sizeof( ulong ) * ((capacity + bits - 1)/bits);
    bl = ( ( bl-1 ) | 15 ) + 1;
    ::munmap( buffer, l + bl + bl );
#else
    ::free( buffer );
    ::free( used );
    ::free( marked );
#endif

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
                    if ( pointers >= 128 )
                        b->x.number = 127;
                    else
                        b->x.number = pointers;
                    b->x.magic = ::magic;
#if defined(ARNT)
                    b->up = 0;
#endif
                    marked[base/bits] &= ~( 1UL << j );
                    used[base/bits] |= ( 1UL << j );
                    taken++;
                    base++;
                    memset( b->payload, 0, pointers*sizeof(void*) );
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


/*! Records that \a p contains at most \a n pointers, all located at
    the start of the object. The rest of the object is not scanned for
    pointers during garbage collection, which can be helpful if the
    object contains either very large string/text data or apparently
    random binary data.

    Scanning long strings is slow. Binary data can give false alarms
    during pointer scanning, which will lead ot memory not being
    freed.
*/

void Allocator::setNumPointers( const void * p, uint n )
{
    if ( n * sizeof( void * ) >= step || n > 127 )
        n = 127;

    ulong i = ((ulong)p - (ulong)buffer) / step;
    if ( i >= capacity )
        return;
    if ( ! (used[i/bits] & 1UL << (i%bits)) )
        return;

    AllocationBlock * m = (AllocationBlock *)block( i );
    if ( m->x.magic != ::magic )
        die( Memory );

    m->x.number = n;
}


/*! This private helper inserts the allocator in the tree used by
    owner().
*/

void Allocator::insert()
{
    if ( !::root ) {
        ::root = this;
        return;
    }

    Allocator * p = ::root;
    while ( p != this ) {
        if ( (ulong)p->buffer < (ulong)buffer ) {
            if ( !p->right )
                p->right = this;
            p = p->right;
        }
        else if ( (ulong)p->buffer > (ulong)buffer ) {
            if ( !p->left )
                p->left = this;
            p = p->left;
        }
    }
}


/*! Returns a pointer to the Allocator in which \a p lies, or a null
    pointer if \a p doesn't seem to be a valid pointer.
*/

Allocator * Allocator::owner( const void * p )
{
    if ( !p )
        return 0;

    Allocator * l = 0;
    Allocator * a = ::root;
    while ( a ) {
        // is a to the left of p, and l even further to the left? move
        // l closer.
        if ( a && (ulong)a->buffer <= (ulong)p &&
             ( !l || (ulong)a->buffer > (ulong)l->buffer ) )
            l = a;
        // move a towards p - left or right
        if ( (ulong)a->buffer < (ulong)p )
            a = a->right;
        else if ( (ulong)a->buffer > (ulong)p )
            a = a->left;
        else
            a = 0;
    }
    // at this point, we know two things:

    // EITHER: on the path from the root towards p, we've visited the
    // node that's closest to p on its left
    if ( l )
        return l;

    // OR: p is to the left of the leftmost node (a)
    return 0;
}


/*! This private helper checks that \a p is a valid pointer to
    unmarked GCable memory, marks it, and puts it on a stack so that
    mark() can process it and add its children to the stack.

    \a u is unused normally. It basically a placeholder since I've
    used a second argument here to many times, for different debugging
    experiements, and grew tired of removing them before submitting.
*/

void Allocator::mark( void * p, void * u )
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
    objects++;
    ::marked += a->step;
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
        if ( !stack )
            die( Memory );
        tos = 0;
    }
    stack[tos++] = b;
#if defined(ARNT)
    b->up = u;
    #else
    u = u; // against warnings
#endif
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
        uint number = b->x.number;
        if ( number == 127 ) {
            Allocator * a = owner( b );
            number = ( a->step - bytes ) / sizeof( void* );
        }
        uint n = 0;
        while ( n < number ) {
            if ( b->payload[n] ) {
                mark( b->payload[n], b );
            }
            n++;
        }
    }
    ::free( stack );
    stack = 0;
    tos = 0;
}


/*! Frees all memory that's no longer in use. This can take some time. */

void Allocator::free()
{
    struct timeval start, afterMark, afterSweep;
    start.tv_sec = 0;
    start.tv_usec = 0;
    afterMark.tv_sec = 0;
    afterMark.tv_usec = 0;
    afterSweep.tv_sec = 0;
    afterSweep.tv_usec = 0;
    gettimeofday( &start, 0 );

    Cache::clearAllCaches();

    total = 0;
    peak = 0;
    uint freed = 0;
    objects = 0;
    ::marked = 0;

    // mark
    uint i = 0;
    while ( i < ::numRoots ) {
        uint o = objects;
        uint m = ::marked;
        mark( ::roots[i].root, 0 );
        mark();
        ::roots[i].objects = objects - o;
        ::roots[i].size = ::marked - m;

        i++;
    }
    gettimeofday( &afterMark, 0 );

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
            a = a->next;
        }
        Allocator * s = 0;
        a = allocators[i];
        while ( a ) {
            Allocator * n = a->next;
            if ( a->taken ) {
                a->next = s;
                s = a;
                blocks++;
            }
            else {
                delete a;
            }
            a = n;
        }
        allocators[i] = s;
        i++;
    }
    gettimeofday( &afterSweep, 0 );

    uint timeToMark = 0;
    uint timeToSweep = 0;
    if ( start.tv_sec ) {
        timeToMark = ( afterMark.tv_sec - start.tv_sec ) * 1000000 +
                     ( afterMark.tv_usec - start.tv_usec );
        timeToSweep = ( afterSweep.tv_sec - afterMark.tv_sec ) * 1000000 +
                      ( afterSweep.tv_usec - afterMark.tv_usec );
    }
    // dumpRandomObject();

    if ( !freed )
        return;

    if ( verbose && ( ::allocated >= 4*1024*1024 ||
                      timeToMark + timeToSweep >= 10000 ) )
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
             fn( peak ) + ". Time needed to mark: " +
             fn( (timeToMark+500)/1000 ) + "ms. To sweep: " +
             fn( (timeToSweep+500)/1000 ) + "ms.",
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
        log( objects, Log::Debug );
    }
    const uint ObjectLimit = 8192;
    if ( verbose && objects > ObjectLimit ) {
        i = 0;
        while ( i < numRoots ) {
            if ( roots[i].objects > ObjectLimit/2 ) {
                String objects = "Root ";
                objects.appendNumber( i );
                objects.append( " (" );
                objects.append( roots[i].name );
                objects.append( ") reaches " );
                objects.appendNumber( roots[i].objects );
                objects.append( " objects, total size " );
                objects.append( String::humanNumber( roots[i].size ) );
                objects.append( "b" );
                log( objects, Log::Debug );
            }
            i++;
        }
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
                }
            }
            i++;
        }
        marked[b] = 0;
        b++;
    }
    base = 0;
}


/*! Returns the amount of memory allocated to hold \a p and any object
    to which p points.

    As a side effect, this marks \a p and the other objects so they
    won't be freed during the next collection.
*/

uint Allocator::sizeOf( void * p )
{
    ::objects = 0;
    ::marked = 0;
    mark( p, 0 );
    mark();
    return ::marked;
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
    ::roots[::numRoots].objects = 0;
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
        roots[i].objects = roots[i+1].objects;
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
