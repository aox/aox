// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CP932
#define CP932

#include "codec.h"


class Cp932Codec
    : public Codec
{
public:
    Cp932Codec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


#endif
