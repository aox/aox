#ifndef USTRING_H
#define USTRING_H

#include "global.h"

class Arena;


class UString {
public:
    UString();
    UString( const UString & );
    ~UString();

    UString & operator=( const UString & );
    UString & operator+=( const UString & str );

    // const, returns zero when used beyond the end
    int operator[]( uint i ) const {
        if ( i >= len )
            return 0;
        return str[i];
    }

    bool isEmpty() const { return len == 0; }
    uint length() const { return len; }

    void append( const UString & );
    void append( const int );

    void reserve( uint );
    void truncate( uint );

    friend inline bool operator==( const UString &, const UString & );

private:
    uint len, max;
    int idx;
    int *str;
    Arena * a;
};


inline bool operator==( const UString & s1, const UString & s2 )
{
    if ( s1.length() != s2.length() )
        return false;
    uint i = 0;
    while ( i < s1.length() ) {
        if ( s1[i] != s2[i] )
            return false;
        i++;
    }
    return true;
}


inline bool operator!=( const UString & s1, const UString & s2 )
{
    return !( s1 == s2 );
}


extern const UString operator+( const UString & a, const UString & b );
extern const UString operator+=( const UString & a, const UString & b );


#endif
