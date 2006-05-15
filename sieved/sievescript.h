// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVESCRIPT_H
#define SIEVESCRIPT_H

#include "global.h"


class SieveScript
    : public Garbage
{
public:
    SieveScript();

private:
    class SieveScriptData * d;
};


#endif
