// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "map.h"

#include <arpa/inet.h> // ntohl

// we need BYTE_ORDER and arpa/inet doesn't give us that on linux, so
// try to coax that out of linux, but use ifdefs so that if we don't
// need endian.h, we don't even try to include it. I hate the
// endianness functions.
#if !defined( BYTE_ORDER )
  #if !defined( __USE_BSD )
    #define __USE_BSD
  #endif
  #include <endian.h>
#endif


/*! \class Map map.h
    The Map template maps from uint to a pointer.

    It is intended to be used for cached database rows: The user
    supplies the row's unique key and the Map supplies a pointer to
    the cached object.

    The implementation is optimized for scattered clusters of values:
    If 1234 is in the map, other integers nearby are assumed to be
    there, too. When this is true, the memory overhead is small and
    speed high. When not, speed remains high.

    The actual implementation is a number of arrays. The key is
    chopped into n-bit chunks and each chunk is used to index into a
    table. The most significant few bits index into the root table.

    n is an implementation constant, not adjustable per Map. At the
    moment it's 6 (and the root table is mostly empty).
*/


/*! \fn Map::Map()
  Creates a new empty Map.
*/


/*! \fn T * Map::find( uint i )

Returns a pointer to the object at index \a i, or a null pointer if
there is no such object. This function does not allocate any memory.
*/

/*! \fn void Map::insert( uint i, T * r )

Inserts \a r into the Map at index \a i. This may cause memory
allocation as the map builds intermediate tree nodes.
*/

/*! \fn void Map::remove( uint i )

Removes the object at index \a i from the Map. This may cause memory
allocation, as it's a thin wrapper around insert( \a i, 0 ).
*/

/*! \fn bool Map::contains( uint i )
Returns true if this map has an object at index \a i, and false if not.
*/

/*! \fn uint Map::count() const
Returns the number of objects in the Map.
*/


/*! \fn void Map::clear()
Removes everything in the map.
*/


/*! \fn uint Map::k( uint i )
Returns \a i with the most significant byte first (AKA network byte
order), useful for PatriciaTree.
*/

/*! \fn uint Map::l()
Returns the number of bits in a uint.
*/


// This static helper returns the uint in network byte order, much
// like ntohl, except that it supports 64-bit uints.

uint uintInNetworkOrder( uint x )
{
    if ( BYTE_ORDER == BIG_ENDIAN )
        return x;
    else if ( sizeof( uint ) <= 4 )
        return ntohl( x );
    else
        return (  (((x) & 0xff00000000000000ull) >> 56)
                | (((x) & 0x00ff000000000000ull) >> 40) 
                | (((x) & 0x0000ff0000000000ull) >> 24)           
                | (((x) & 0x000000ff00000000ull) >> 8)            
                | (((x) & 0x00000000ff000000ull) << 8)            
                | (((x) & 0x0000000000ff0000ull) << 24)           
                | (((x) & 0x000000000000ff00ull) << 40)           
                | (((x) & 0x00000000000000ffull) << 56));
}
