// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef STRING_H
#define STRING_H

#include "global.h"


class StringData {
private:
    StringData(): str( 0 ), len( 0 ), max( 0 ) {}

    friend class String;
    char * str;
    uint len;
    uint max;
};


class String {
public:
    String();
    String( const char * );
    String( const char *, uint );
    String( const String & );
    ~String();

    String & operator=( const String & );
    String & operator=( const char * );
    String & operator+=( const String & str ) { append( str ); return *this; }

    // const, returns zero when used beyond the end
    char operator[]( uint i ) const {
        if ( !d )
            return 0;
        if ( i >= d->len )
            return 0;
        return d->str[i];
    }

    char at( uint i ) const { return (*this)[i]; }

    bool isEmpty() const { return length() == 0; }
    uint length() const { if ( !d ) return 0; return d->len; }
    const char *data() const { if (!d) return 0; return (const char*)d->str; }
    const char *cstr();

    String lower() const;
    String upper() const;
    String headerCased() const;
    String mid( uint, uint = UINT_MAX ) const;
    String simplified() const;
    String stripWSP() const;
    String stripCRLF() const;
    String hex() const;
    bool isQuoted( char = '"', char = '\\' ) const;
    String unquoted( char = '"', char = '\\' ) const;
    String quoted( char = '"', char = '\\' ) const;

    enum Boring { Totally, IMAP, MIME };
    bool boring( Boring = Totally ) const;

    bool startsWith( const String & ) const;
    bool startsWith( const char * ) const;
    bool endsWith( const String & ) const;
    bool endsWith( const char * ) const;
    uint number( bool *, uint = 10 ) const;
    static String fromNumber( uint, uint = 10 );

    int find( char, int=0 ) const;
    int find( const String &, int=0 ) const;

    void append( char );
    void appendNumber( int, int = 10 );
    void appendNumber( uint, int = 10 );
    void append( const String & );
    void append( const char *, uint );

    void reserve( uint );
    void truncate( uint );

    enum Encoding { Binary, Base64, QuotedPrintable };
    String encode( Encoding, uint = 0 ) const;
    String decode( Encoding ) const;

    String de64() const;
    String e64( uint = 0 ) const;
    String deQP() const;
    String eQP() const;
    bool needsQP() const;

    friend inline bool operator==( const String &, const String & );
    friend bool operator==( const String &, const char * );

    bool operator<( const String & ) const;
    bool operator>( const String & ) const;
    bool operator<=( const String & ) const;
    bool operator>=( const String & ) const;

    int compare( const String & ) const;

    void detach() { if ( !modifiable() ) reserve( length() ); }

    bool modifiable() const { return d && d->max > 0; }

private:
    StringData * d;
};


// since operator== is called so often, we provide fastish inlines
inline bool operator==( const String & a, const String & b ) {
    if ( a.length() != b.length() )
        return false;
    uint i = 0;
    while ( i < a.length() && a[i] == b[i] )
        i++;
    if ( i < a.length() )
        return false;
    return true;
}


inline bool operator==( const String & a, const char * b ) {
    if ( !b ) {
        if ( a.length() == 0 )
            return true;
        return false;
    }
    uint i = 0;
    while ( i < a.length() && a[i] == b[i] && b[i] != '\0' )
        i++;
    if ( i < a.length() )
        return false;
    if ( b[i] != '\0' )
        return false;
    return true;
}


inline bool operator==( const char * a, const String & b ) {
    return b == a;
}


inline bool operator!=( const String & a, const char * b ) {
    return !( a == b );
}


inline bool operator!=( const char * a, const String & b ) {
    return !( b == a );
}


inline bool operator!=( const String & a, const String & b ) {
    return !( a == b );
}


extern const String operator+( const String & a, const String & b );
extern const String operator+=( const String & a, const String & b );


inline String fn( uint n, uint b = 10 )
{
    return String::fromNumber( n, b );
}


#endif
