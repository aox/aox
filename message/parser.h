// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PARSER_H
#define PARSER_H

#include "string.h"


class UString;


class Parser822
{
public:
    Parser822( const String & os ): s(os), i(0), mime( false ) {}

    void setIndex( uint ni ) { i = ni; }
    uint index() const { return i; }

    void setString( const String & ns ) { s = ns; setIndex( 0 ); }
    operator String() { return s; }

    void step() { setIndex( i + 1 ); }
    void setMime( bool );
    bool isMime() const { return mime; }

    void stepPast( const char *, const char * );
    void whitespace();

    String comment();
    String string();
    String dotAtom();
    String phrase();
    char character();
    String domain();
    String atom();
    String mimeToken();
    String mimeValue();
    UString encodedWord();
    UString text();

    char next() const { return s[i]; }

    bool isAtext( char ) const;

    bool atEnd() const { return i >= s.length(); }

    bool hasError() { return false; }

private:
    void error( const char * ) {}
    String s;
    uint i;
    bool mime;
};


#endif
