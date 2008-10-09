// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DICT_H
#define DICT_H

#include "patriciatree.h"
#include "string.h"


template<class T>
class Dict: public PatriciaTree<T> {
public:
    Dict(): PatriciaTree<T>() {}

    T * find( const String & s ) const {
        return PatriciaTree<T>::find( s.data(), s.length() * 8 );
    }
    void insert( const String & s, T* r ) {
        PatriciaTree<T>::insert( s.data(), s.length() * 8, r );
    }
    T* take( const String & s ) {
        return PatriciaTree<T>::take( s.data(), s.length() * 8 );
    }
    bool contains( const String & s ) const {
        return find( s ) != 0;
    }

private:
    // operators explicitly undefined because there is no single
    // correct way to implement them.
    Dict< T > &operator =( const Dict< T > & ) { return *this; }
    bool operator ==( const Dict< T > & ) const { return false; }
    bool operator !=( const Dict< T > & ) const { return false; }
};


#endif
