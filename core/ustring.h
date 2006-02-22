// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef USTRING_H
#define USTRING_H

#include "global.h"

class String;


class UString
    : public Garbage
{
public:
    UString();
    UString( const UString & );
    ~UString();

    UString & operator=( const UString & );
    UString & operator+=( const UString & str );

    // const, returns zero when used beyond the end
    uint operator[]( uint i ) const {
        if ( i >= len )
            return 0;
        return str[i];
    }

    bool isEmpty() const { return len == 0; }
    uint length() const { return len; }

    void append( const UString & );
    void append( const uint );

    void reserve( uint );
    void truncate( uint = 0 );

    friend inline bool operator==( const UString &, const UString & );
    friend inline bool operator==( const UString &, const char * );

    String ascii() const;

    UString mid( uint, uint = UINT_MAX ) const;
    uint number( bool *, uint = 10 ) const;
    
private:
    uint len;
    uint max;
    uint *str;
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


inline bool operator==( const UString & s1, const char * s2 )
{
    if ( !s2 )
        return false;
    uint i = 0;
    while ( i < s1.length() ) {
        if ( s2[i] < 32 || s2[i] >= 127 || s1[i] != s2[i] )
            return false;
        i++;
    }
    if ( s2[i] )
        return false;
    return true;
}


inline bool operator!=( const UString & s1, const char * s2 )
{
    return !( s1 == s2 );
}


extern const UString operator+( const UString & a, const UString & b );
extern const UString operator+=( const UString & a, const UString & b );


#endif
