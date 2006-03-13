// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CODEC_H
#define CODEC_H

class UString;

#include "global.h"
#include "string.h"


class Codec
    : public Garbage
{
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
    String error() const;
    void recordError( uint );
    void recordError( uint, const String & );
    void recordError( uint, uint );
    void recordError( const String & );

    static Codec * byName(  const String & );
    static Codec * byString( const UString & );
    static Codec * byString( const String & );

    String name() { return n; }

private:
    State s;
    String n;
    String e;
};


class TableCodec: public Codec {
protected:
    TableCodec( const uint * table, const char * cs )
        : Codec( cs ), t( table ) {}

public:
    String fromUnicode( const UString & );
    UString toUnicode( const String & );

private:
    const uint * t;
};


class AsciiCodec: public Codec {
public:
    AsciiCodec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


#endif
