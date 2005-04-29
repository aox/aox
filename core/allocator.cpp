// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "allocator.h"

#include "sys.h"
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
            uint marked: 1;
        } x;
        uint y;
    };
    void* payload[1];
};


const uint SizeLimit = 512 * 1024 * 1024;


void *operator new( uint s )
{
    return ::alloc( s, s / sizeof( void* ) );
}

void *operator new[]( uint s )
{
    return ::alloc( s, s / sizeof( void* ) );
}

void operator delete( void * )   {}
void operator delete[]( void * ) {}


static int total;
static uint allocated;


void * alloc( uint s, uint n )
{
    if ( s > SizeLimit )
        die( Memory );
    if ( n > s / sizeof( void* ) )
        n = s / sizeof( void* );
    Allocator * a = Allocator::allocator( s );
    void * p = a->allocate( s, n );
    if ( ( ( total + allocated + s ) & 0xfff00000 ) >
         ( ( total + allocated ) & 0xfff00000 ) )
    {
        // this is a good place to put a breakpoint when we want to
        // find out who allocates memory.
        fprintf( stderr, "" );
    }
    allocated += a->chunkSize();
    return p;
}


void dealloc( void * p )
{
    Allocator * a = Allocator::owner( p );
    if ( a )
        a->deallocate( p );
}


const uint bytes = sizeof(uint);
const uint bits = 8 * sizeof(uint);
const uint magic = 0x7d34;


static Allocator * allocators[32];
static uint heapStart;
static uint heapLength;


static struct {
    void * root;
    const char * name;
    uint size;
} roots[1024];

static uint numRoots;

static Allocator * byStart[0x1000];

static bool verbose;


/*! Returns a pointer to the Allocator responsible for \a size. \a
    size need not be rounded.
*/

Allocator * Allocator::allocator( uint size )
{
    uint i = 0;
    while ( size + bytes > 8U << i )
        i++;
    if ( !allocators[i] ) {
        Allocator * a = new Allocator( 8 << i );
        allocators[i] = a;
        if ( verbose )
            log( "Allocating " + fn( a->capacity * a->step ) +
                 " bytes at 0x" + fn( (uint)a->buffer, 16 ) +
                 " for " + fn( a->capacity ) + " " +
                 fn( a->step - bytes ) + "-byte objects\n",
                 Log::Debug );
    }
    return allocators[i];
}


/*! \class Allocator allocator.h

    The Allocator class provides Mailstore's memory allocation system,
    a simple garbage collector for event-driven servers.

    Our GC system is based on the notion of eternal objects and safe
    GC points. Eternal objects must
    be declared by calling addEternal.

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
    of size at most \a s - sizeof(int) bytes.
*/

Allocator::Allocator( uint s )
    : base( 0 ), step( s ), taken( 0 ), capacity( 0 ),
      bitmap( 0 ), buffer( 0 ),
      next( 0 )
{
    if ( s < 262144 )
        capacity = 0x100000 / ( s );
    else
        capacity = 1;
    uint l = capacity * s;
    buffer = ::malloc( l );
    uint bl = sizeof( uint ) * (capacity + bits - 1)/bits;
    bitmap = (uint*)::malloc( bl );

    memset( buffer, 0, l );
    memset( bitmap, 0, bl );

    uint hs = (uint)buffer;
    uint he = hs + l;
    if ( heapStart ) {
        if ( ::heapStart < hs )
            hs = ::heapStart;
        if ( ::heapStart + ::heapLength > he )
            he = ::heapStart + ::heapLength;
    }
    ::heapStart = hs;
    ::heapLength = he - hs;

    ::byStart[(uint)buffer >> 20] = this;
}



/*! Destroys the object and frees its allocated memory. Does NOT
    change the heap start/end variables. */

Allocator::~Allocator()
{
    ::byStart[(uint)buffer >> 20] = 0;

    ::free( buffer );
    ::free( bitmap );

    next = 0;
    bitmap = 0;
    buffer = 0;
}


/*! Allocates a chunk of memory, notes that at most \a size bytes are
    in use, and returns a pointer to it.
*/

void * Allocator::allocate( uint size, uint pointers )
{
    if ( taken < capacity ) {
        while ( base < capacity ) {
            uint bm = bitmap[base/bits];
            if ( bm != UINT_MAX ) {
                uint j = base%bits;
                while ( bm & ( 1 << j ) )
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
                    b->x.marked = false;
                    bitmap[base/bits] |= ( 1 << j );
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
    uint i = ((uint)p - (uint)buffer) / step;
    if ( i >= capacity )
        return;
    if ( ! (bitmap[i/bits] & 1 << (i%bits)) )
        return;

    AllocationBlock * m = (AllocationBlock *)block( i );
    if ( m->x.magic != ::magic ) {
        if ( verbose )
            log( "Memory corrupt at 0x" + fn( (uint)m, 16 ),
                 Log::Disaster );
        die( Memory );
    }
    bitmap[i/bits] &= ~(1 << i);
    taken--;
    m->x.magic = 0;
    m->x.marked = false;

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
    uint q = (uint)p - ::heapStart;
    if ( q >= ::heapLength )
        return 0;
    uint ai = (uint)p >> 20;
    Allocator * a = 0;
    do {
        a = (Allocator*)(::byStart[ai]);
        ai--;
    } while ( ai && ( !a || (uint)a->buffer > (uint)p ) );
    return a;
}


/*! This private helper marks \a p and (recursively) all objects to
    which \a p points.
*/

void Allocator::mark( void * p )
{
    Allocator * a = owner( p );
    // a is the allocator we may want. does its area encompass p?
    if ( !a || (uint)a->buffer > (uint)p )
        return;
    // perhaps, but let's look closer
    uint i = ((uint)p - (uint)a->buffer) / a->step;
    if ( i >= a->capacity )
        return;
    if ( ! (a->bitmap[i/bits] & 1 << (i%bits)) )
        return;
    // fine. we have the block of memory.
    AllocationBlock * b = (AllocationBlock*)a->block( i );
    // does it have our magic marker?
    if ( b->x.magic != ::magic ) {
        if ( verbose )
            log( "Would have marked non-object at 0x" + fn( (uint)b, 16 ) +
                 " because of a pointer to 0x" + fn( (uint)p, 16 ),
                 Log::Disaster );
        die( Memory );
        return;
    }
    // is it already marked?
    if ( b->x.marked )
        return;
    // no. mark it
    b->x.marked = true;
    // ... and its children
    uint n = b->x.number;
    while ( n ) {
        n--;
        if ( b->payload[n] )
            mark( b->payload[n] );
    }
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
    // and sweep
    i = 0;
    while ( i < 32 ) {
        Allocator * a = allocators[i];
        Allocator * p = 0;
        while ( a ) {
            uint taken = a->taken;
            if ( a->taken )
                a->sweep();
            freed = freed + ( taken - a->taken ) * a->step;
            total = total + a->taken * a->step;
            objects += a->taken;
            Allocator * n = a->next;
            if ( taken == 0 && a->taken == 0 && p ) {
                p->next = a->next;
                delete a;
            }
            a = n;
        }
        i++;
    }

    if ( !freed )
        return;

    if ( verbose )
        log( "Allocator: allocated " + fn( ::allocated ) + " then freed " +
             fn( freed ) + " bytes, leaving " +
             fn( total ) + " bytes allocated in " +
             fn( objects ) + " objects",
             Log::Info );
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
        while ( i < bits && bitmap[b] ) {
            AllocationBlock * m
                = (AllocationBlock *)block( b * bits + i );
            if ( m && (bitmap[b] & (1<<i)) ) {
                if ( m->x.magic != ::magic ) {
                    if ( verbose )
                        log( "Memory corrupt at 0x" + fn( (uint)m, 16 ),
                             Log::Disaster );
                    die( Memory );
                }
                if ( !m->x.marked ) {
                    bitmap[b] &= ~(1 << i);
                    taken--;
                    m->x.magic = 0;
                }
                m->x.marked = false;
            }
            i++;
        }
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
    return (void *)(i * step + (uint)buffer);
}


void Allocator::operator delete( void * p )
{
    //
}


void *Allocator::operator new( uint )
{
    return ::malloc( sizeof( Allocator ) );
}


/*! \fn uint Allocator::rounded( uint size )

    Returns the biggest number of bytes which can be allocated at the
    same effective cost as \a size.

    Suppose allocating 24, 25 or 28 bytes all cause Allocator to use
    32 bytes, but 29 causes Allocator to use 48. Then rounded(24),
    rounded(25) and rounded(28) all return 28, while rounded(29) might
    return something like 44.

    This can be used by String and UString to optimize their memory
    usage. Perhaps also by other classes.
*/


/*! Records that \a *p is an allocation root, i.e. that whatever it
    points to is a valid object.
*/

void Allocator::addEternal( void * p, const char * t )
{
    ::roots[::numRoots].root = p;
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

void Allocator::removeRoot( void * p )
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

void Allocator::removeRoot( const void * p )
{
    removeRoot( (void*)p );
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


/*! Returns the amount of memory gobbled up when this Allocator
    allocates memory. This is a little bigger than the biggest object
    this Allocator can provide.
*/

uint Allocator::chunkSize() const
{
    return step;
}
