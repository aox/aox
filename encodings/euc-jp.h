// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef EUCJP
#define EUCJP

#include "codec.h"


class EucJpCodec
    : public Codec
{
public:
    EucJpCodec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


#endif
