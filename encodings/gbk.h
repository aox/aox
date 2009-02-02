// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
