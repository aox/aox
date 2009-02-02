// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ISO2022JP
#define ISO2022JP

#include "codec.h"


class Iso2022JpCodec
    : public Codec
{
public:
    Iso2022JpCodec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


#endif
