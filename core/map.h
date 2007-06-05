// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAP_H
#define MAP_H

#include "global.h"


class MapTable
    : public Garbage
{ // helper class for Map
public:
    MapTable();
    void * find( uint );
    void insert( uint, void * );
    uint count( uint ) const;
    void clear();

    static const uint Slice = 6;
    static const uint Size = 1 << Slice;

private:
    MapTable * data[Size];
};


template<class T>
class Map
    : public Garbage
{
public:
    Map() {} // more?

    T * find( uint i ) { return (T*)(t.find( i )); }
    void insert( uint i, T* r ) { t.insert( i, r ); }
    void remove( uint i ) { t.insert( i, 0 ); }
    bool contains( uint i ) { return find( i ) != 0; }
    uint count() const { return t.count( sizeof(uint)*8/MapTable::Slice ); }
    void clear() { t.clear(); }

private:
    MapTable t;
private:
    // operators explicitly undefined because there is no single
    // correct way to implement them.
    Map< T > &operator =( const Map< T > & ) { return *this; }
    bool operator ==( const Map< T > & ) const { return false; }
    bool operator !=( const Map< T > & ) const { return false; }
};


#endif
