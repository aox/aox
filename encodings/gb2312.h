// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef GB2312
#define GB2312

#include "codec.h"


class Gb2312Codec
    : public Codec
{
public:
    Gb2312Codec();

    String fromUnicode( const UString & );
    UString toUnicode( const String & );
};


#endif
