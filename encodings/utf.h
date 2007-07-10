// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef UTF_H
#define UTF_H

#include "codec.h"


class Utf8Codec: public Codec
{
public:
    Utf8Codec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );

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

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
private:
    bool be;
    bool bom;
};


class Utf16LeCodec: public Codec
{
public:
    Utf16LeCodec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


class Utf16BeCodec: public Codec
{
public:
    Utf16BeCodec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


class Utf7Codec: public Codec
{
public:
    Utf7Codec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );

protected:
    String e( const UString & );
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
