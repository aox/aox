// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef EUCKR_H
#define EUCKR_H

#include "codec.h"


class EucKrCodec
    : public Codec
{
public:
    EucKrCodec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


#endif
