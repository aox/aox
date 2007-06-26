// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef USTRING_H
#define USTRING_H

#include "global.h"

class String;


class UStringData
    : public Garbage
{
private:
    UStringData(): str( 0 ), len( 0 ), max( 0 ) {}
    UStringData( int );

    friend class UString;
    friend bool operator==( const class UString &, const class UString & );
    friend bool operator==( const UString &, const char * );
    void * operator new( size_t, uint );
    void * operator new( size_t s ) { return Garbage::operator new( s); }

    uint * str;
    uint len;
    uint max;
};


class UString
    : public Garbage
{
public:
    UString();
    UString( const UString & );
    ~UString();

    UString & operator=( const UString & );
    UString & operator+=( const UString & str );

    void operator delete( void * );

    // const, returns zero when used beyond the end
    uint operator[]( uint i ) const {
        if ( !d || i >= d->len )
            return 0;
        return d->str[i];
    }

    bool isEmpty() const { return !d || d->len == 0; }
    uint length() const { return d ? d->len : 0; }

    void append( const UString & );
    void append( const uint );

    void reserve( uint );
    void truncate( uint = 0 );

    bool isAscii() const;
    String ascii() const;
    String utf8() const;

    UString mid( uint, uint = UINT_MAX ) const;
    uint number( bool *, uint = 10 ) const;
    UString simplified() const;

    inline void detach() { if ( !modifiable() ) reserve( length() ); }

    bool modifiable() const { return d && d->max > 0; }

private:
    void reserve2( uint );


private:
    class UStringData * d;
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
