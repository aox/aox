// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SHIFTJIS
#define SHIFTJIS

#include "codec.h"


class ShiftJisCodec
    : public Codec
{
public:
    ShiftJisCodec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


#endif
