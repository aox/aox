// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef UTF_H
#define UTF_H

#include "codec.h"


class Utf8Codec: public Codec
{
public:
    Utf8Codec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );

protected:
    bool pgutf;
};


class PgUtf8Codec: public Utf8Codec
{
public:
    PgUtf8Codec();
};


class Utf16Codec: public Codec
{
public:
    Utf16Codec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
private:
    bool be;
    bool bom;
};


class Utf16LeCodec: public Codec
{
public:
    Utf16LeCodec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


class Utf16BeCodec: public Codec
{
public:
    Utf16BeCodec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


class Utf7Codec: public Codec
{
public:
    Utf7Codec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );

protected:
    EString e( const UString & );
    Utf7Codec( bool );

private:
    bool broken;
};


class MUtf7Codec: public Utf7Codec
{
public:
    MUtf7Codec();
};


#endif
