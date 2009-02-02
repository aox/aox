// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CP950
#define CP950

#include "codec.h"


class Cp950Codec
    : public Codec
{
public:
    Cp950Codec();

    EString fromUnicode( const UString & );
    UString toUnicode( const EString & );
};


#endif
