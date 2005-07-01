// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef RESET_H
#define RESET_H

#include "command.h"


class XOryxReset
    : public Command
{
public:
    XOryxReset(): d( 0 ) {}
    void execute();

    class XOryxResetData * d;
};


#endif
