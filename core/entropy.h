// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ENTROPY_H
#define ENTROPY_H

#include "string.h"


class Entropy
{
public:
    static void setup();
    static String asString( uint );
    static uint asNumber( uint );
};

#endif
