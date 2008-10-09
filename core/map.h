// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAP_H
#define MAP_H

#include "global.h"
#include "patriciatree.h"


extern uint uintInNetworkOrder( uint );


template<class T>
class Map
    : public PatriciaTree<T>
{
public:
    Map() {} // more?

    T * find( uint i ) {
        uint x=k(i);
        return PatriciaTree<T>::find( (char*)&x, l() );
    }
    void insert( uint i, T * r ) {
        uint x=k(i);
        PatriciaTree<T>::insert( (char*)&x,l(),r );
    }
    void remove( uint i ) {
        uint x=k(i);
        PatriciaTree<T>::remove( (char*)&x, l() );
    }
    bool contains( uint i ) { return find( i ) != 0; }

private:
    static uint k( uint i ) { return ::uintInNetworkOrder( i ); }
    static uint l() { return 8 * sizeof( uint ); }

private:
    // operators explicitly undefined because there is no single
    // correct way to implement them.
    Map< T > &operator =( const Map< T > & ) { return *this; }
    bool operator ==( const Map< T > & ) const { return false; }
    bool operator !=( const Map< T > & ) const { return false; }
};


#endif
