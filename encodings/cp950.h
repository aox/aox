// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CP950
#define CP950

#include "codec.h"


class Cp950Codec
    : public Codec
{
public:
    Cp950Codec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


#endif
