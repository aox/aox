// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CODEC_H
#define CODEC_H

class UString;

#include "global.h"
#include "estring.h"


class Codec
    : public Garbage
{
public:
    Codec( const char * );
    virtual ~Codec();

    virtual EString fromUnicode( const UString & ) = 0;
    virtual UString toUnicode( const EString & ) = 0;

    bool wellformed() const { return state() == Valid; }
    bool valid() const { return state() != Invalid; }

    virtual void reset();

    enum State { Valid, BadlyFormed, Invalid, Aborted };
    void setState( State st ) { s = st; }
    State state() const { return s; }
    EString error() const;
    void recordError( uint );
    void recordError( uint, const EString & );
    void recordError( uint, uint );
    void recordError( const EString & );

    static Codec * byName(  const EString & );
    static Codec * byString( const UString & );
    static Codec * byString( const EString & );

    EString name() const { return n; }

    void append( UString &, uint );
    void mangleTrailingSurrogate( UString & );

    static class EStringList * allCodecNames();

private:
    State s;
    EString n;
    EString e;
    bool a;
};


class TableCodec: public Codec {
protected:
    TableCodec( const uint * table, const char * cs )
        : Codec( cs ), t( table ) {}

public:
    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );

private:
    const uint * t;
};


class AsciiCodec: public Codec {
public:
    AsciiCodec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


#endif
