// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CP949
#define CP949

#include "codec.h"


class Cp949Codec
    : public Codec
{
public:
    Cp949Codec( const char * = 0 );

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


#endif
