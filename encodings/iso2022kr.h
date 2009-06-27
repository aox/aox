// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ISO2022KR_H
#define ISO2022KR_H

#include "codec.h"


class Iso2022KrCodec
    : public Codec
{
public:
    Iso2022KrCodec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


#endif
