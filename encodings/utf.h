// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef UTF_H
#define UTF_H

#include "codec.h"


class Utf8Codec: public Codec
{
public:
    Utf8Codec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


#endif
