// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "map.h"

#include "list.h"


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

/*! \fn void Map::insert( uint i, T* r )

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


/*! \class MapTable map.h
  The MapTable class is a helper for Map.

  Map is meant to be fully inlined, as all good templates are, so it
  uses the small array class MapTable to do its work.

  MapTable implements a wide fixed-depth tree; see Map.
*/

/*! Creates an empty MapTable. */

MapTable::MapTable()
{
    uint i = 0;
    while( i < Size )
        data[i++] = 0;
}


/*! Finds \a i in this MapTable. */

void * MapTable::find( uint i )
{
    int o = 8*sizeof(uint)/Slice;
    MapTable * t = this;
    uint n = 0;
    while ( o >= 0 ) {
        n = (i >> (o*Slice))%Size;
        if ( t->data[n] == 0 )
            return 0;
        t = t->data[n];
        o--;
    }
    return t->data[n];
}


/*! Inserts \a r at index \a i into this MapTable. */

void MapTable::insert( uint i, void * r )
{
    int o = 8*sizeof(uint)/Slice;
    MapTable * t = this;
    uint n = 0;
    while ( o >= 0 ) {
        n = (i >> (o*Slice))%Size;
        if ( t->data[n] == 0 )
            t->data[n] = new MapTable;
        t = t->data[n];
        o--;
    }
    t->data[n] = (MapTable*)r; // nasty, but...
}


/*! Returns the number of elements in the map. \a l is the map level;
    it is 0 for the leaf table and nonzero for all intermediate tables
    in the tree. */

uint MapTable::count( uint l ) const
{
    uint i = 0;
    uint r = 0;
    while ( i < Size ) {
        if ( data[i] == 0 )
            ;
        else if ( l > 0 )
            r += data[i]->count( l - 1 );
        else
            r++;
        i++;
    }
    return r;
}


