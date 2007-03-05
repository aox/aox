// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ISO2022KR_H
#define ISO2022KR_H

#include "codec.h"


class Iso2022KrCodec
    : public Codec
{
public:
    Iso2022KrCodec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


#endif
