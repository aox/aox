#ifndef DICT_H
#define DICT_H

#include "string.h"
#include "ustring.h"


class DictBase
{
protected:
    DictBase();

    bool contains( const String & ) const;
    void * find( const String & ) const;
    void insert( const String & s, void* r );
    void * take( const String & );

public:
    void resize( uint );

private:
    static uint hash( const String & );

private:
    class DictBaseData * d;
};


template<class T>
class Dict: public DictBase {
public:
    Dict() {} // more?

    T * find( const String & s ) const { return (T*)DictBase::find( s ); }
    void insert( const String & s, T* r ) { DictBase::insert( s, r ); }
    T* take( const String & s ) { return (T*)DictBase::take( s ); }
    bool contains( const String & s ) const {
        return DictBase::contains( s );
    }

private:
    // operators explicitly undefined because there is no single
    // correct way to implement them.
    Dict< T > &operator =( const Dict< T > & ) { return *this; }
    bool operator ==( const Dict< T > & ) const { return false; }
    bool operator !=( const Dict< T > & ) const { return false; }
};


#endif
