// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CODEC_H
#define CODEC_H

class UString;

#include "global.h"
#include "string.h"


class Codec {
public:
    Codec( const char * );
    virtual ~Codec();

    virtual String fromUnicode( const UString & ) = 0;
    virtual UString toUnicode( const String & ) = 0;

    bool wellformed() const { return state() == Valid; }
    bool valid() const { return state() != Invalid; }

    virtual void reset();

    enum State { Valid, BadlyFormed, Invalid };
    void setState( State st ) { s = st; }
    State state() const { return s; }

    static Codec * byName( const String & );
    static Codec * byString( const UString & );

    String name() { return n; }

private:
    State s;
    String n;
};


class TableCodec: public Codec {
protected:
    TableCodec( const int * table, const char * cs )
        : Codec( cs ), t( table ) {}

public:
    String fromUnicode( const UString & );
    UString toUnicode( const String & );

private:
    const int * t;
};


class AsciiCodec: public Codec {
public:
    AsciiCodec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


#endif
