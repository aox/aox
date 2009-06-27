// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ENTROPY_H
#define ENTROPY_H

#include "estring.h"


class Entropy
    : public Garbage
{
public:
    static void setup();
    static EString asString( uint );
    static uint asNumber( uint );
};

#endif
