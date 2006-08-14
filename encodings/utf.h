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


#endif
