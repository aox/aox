// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVECOMMAND_H
#define SIEVECOMMAND_H

#include "global.h"


class SieveCommand
    : public Garbage
{
public:
    enum Type { Action, If, Require, Stop };

    SieveCommand( Type type );

private:
    class SieveCommandData * d;
};


#endif
