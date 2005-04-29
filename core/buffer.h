// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef BUFFER_H
#define BUFFER_H

#include "global.h"
#include "list.h"


class String;


class Buffer {
public:
    Buffer();

    void append( const String & );
    void append( const char *, uint = 0 );

    void read( int );
    void write( int );

    bool eof() const;
    uint size() const { return bytes; }
    void remove( uint );
    String string( uint ) const;
    String * removeLine( uint = 0 );

    char operator[]( uint i ) const {
        if ( i >= bytes )
            return 0;

        i += firstused;
        Vector *v = vecs.firstElement();
        if ( v && v->len > i )
            return *( v->base + i );

        return at( i );
    }

private:
    char at( uint ) const;

private:
    struct Vector {
        Vector() : base( 0 ), len( 0 ) {}
        char *base;
        uint len;
    };

    List< Vector > vecs;
    uint firstused, firstfree;
    bool seenEOF;
    uint bytes;
};


#endif
