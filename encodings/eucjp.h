// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef EUCJP
#define EUCJP

#include "codec.h"


class EucJpCodec
    : public Codec
{
public:
    EucJpCodec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


#endif
