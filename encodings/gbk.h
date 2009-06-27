// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef GBK
#define GBK

#include "codec.h"


class GbkCodec
    : public Codec
{
public:
    GbkCodec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


#endif
