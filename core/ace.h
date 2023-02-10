// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef ACE_H
#define ACE_H

#include "global.h"

class UString;


class ACE
    : public Garbage
{
public:
    //static EString encode(UString input);
    static UString decode(const UString & input);
};


#endif
