// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ESTRING_H
#define ESTRING_H

#include "global.h"


class EStringData
    : public Garbage
{
private:
    EStringData(): str( 0 ), len( 0 ), max( 0 ) {
        setFirstNonPointer( &len );
    }
    EStringData( int );

    friend class EString;
    friend bool operator==( const class EString &, const class EString & );
    friend bool operator==( const class EString &, const char * );
    void * operator new( size_t, uint );
    void * operator new( size_t s ) { return Garbage::operator new( s); }

    char * str;
    uint len;
    uint max;
};


class EString
    : public Garbage
{
public:
    EString();
    EString( const char * );
    EString( const char *, uint );
    EString( const EString & );
    ~EString();

    EString & operator=( const EString & );
    EString & operator=( const char * );
    EString & operator+=( const EString & str ) { append( str ); return *this; }

    void operator delete( void * );

    // const, returns zero when used beyond the end
    inline char operator[]( uint i ) const {
        if ( !d )
            return 0;
        if ( i >= d->len )
            return 0;
        return d->str[i];
    }

    inline char at( uint i ) const { return (*this)[i]; }

    inline bool isEmpty() const { return !d || !d->len; }
    inline uint length() const { return d ? d->len : 0; }
    inline uint capacity() const { return d ? d->max : 0; }
    inline const char * data() const { return d ? (const char*)d->str : 0; }
    const char * cstr();
    const char * cstr() const;

    EString lower() const;
    EString upper() const;
    EString headerCased() const;
    EString mid( uint, uint = UINT_MAX ) const;
    EString simplified() const;
    EString trimmed() const;
    EString stripCRLF() const;
    EString hex() const;
    bool isQuoted( char = '"', char = '\\' ) const;
    EString unquoted( char = '"', char = '\\' ) const;
    EString quoted( char = '"', char = '\\' ) const;

    enum Boring { Totally, IMAP, MIME };
    bool boring( Boring = Totally ) const;

    bool startsWith( const EString & ) const;
    bool startsWith( const char * ) const;
    bool endsWith( const EString & ) const;
    bool endsWith( const char * ) const;
    uint number( bool *, uint = 10 ) const;
    static EString fromNumber( int64, uint = 10 );
    void appendNumber( int64, uint = 10 );
    static EString humanNumber( int64 );

    int find( char, int=0 ) const;
    int find( const EString &, int=0 ) const;
    bool contains( const EString & ) const;
    bool contains( const char ) const;
    bool containsWord( const EString & ) const;
    EString section( const EString &, uint ) const;

    void replace( const EString &, const EString & );

    void append( char );
    void appendNumber( int, int = 10 );
    void appendNumber( uint, int = 10 );
    void append( const EString & );
    void append( const char *, uint );
    void append( const char * );

    void prepend( const EString & );

    void reserve( uint );
    void reserve2( uint );
    void truncate( uint = 0 );
    void setLength( uint );

    enum Encoding { Binary, Base64, QP, Uuencode };
    EString encoded( Encoding, uint = 0 ) const;
    EString decoded( Encoding ) const;

    EString eURI() const;
    EString deURI() const;
    EString de64() const;
    EString deUue() const;
    EString e64( uint = 0 ) const;
    EString deQP( bool = false ) const;
    EString eQP( bool = false, bool = false ) const;
    bool needsQP() const;

    friend inline bool operator==( const EString &, const EString & );
    friend bool operator==( const EString &, const char * );

    bool operator<( const EString & ) const;
    bool operator>( const EString & ) const;
    bool operator<=( const EString & ) const;
    bool operator>=( const EString & ) const;

    bool operator<( const char * ) const;

    int compare( const EString & ) const;

    inline void detach() { if ( !modifiable() ) reserve( length() ); }

    bool modifiable() const { return d && d->max > 0; }

    void print() const;

    EString anonymised() const;

    EString crlf() const;

    EString wrapped( uint linelength,
                    const EString & firstPrefix, const EString & otherPrefix,
                    bool spaceAtEOL ) const;

private:
    EStringData * d;
};


// since operator== is called so often, we provide fastish inlines
inline bool operator==( const EString & a, const EString & b ) {
    uint al = a.length();
    uint bl = b.length();
    if ( !al && !bl )
        return true;
    if ( !al || !bl || al != bl )
        return false;
    if ( a.d == b.d )
        return true;
    uint i = 0;
    while ( i < al && i < bl && a.d->str[i] == b.d->str[i] )
        i++;
    if ( i < al )
        return false;
    return true;
}


inline bool operator==( const EString & a, const char * b ) {
    uint al = a.length();
    if ( !b || !*b ) {
        if ( al == 0 )
            return true;
        return false;
    }
    uint i = 0;
    while ( i < al && a.d->str[i] == b[i] && b[i] != '\0' )
        i++;
    if ( i < al )
        return false;
    if ( b[i] != '\0' )
        return false;
    return true;
}


inline bool operator==( const char * a, const EString & b ) {
    return b == a;
}


inline bool operator!=( const EString & a, const char * b ) {
    return !( a == b );
}


inline bool operator!=( const char * a, const EString & b ) {
    return !( b == a );
}


inline bool operator!=( const EString & a, const EString & b ) {
    return !( a == b );
}


extern const EString operator+( const EString & a, const EString & b );
extern const EString operator+=( const EString & a, const EString & b );


inline EString fn( int64 n, uint b = 10 )
{
    return EString::fromNumber( n, b );
}


#endif
