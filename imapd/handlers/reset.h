// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef RESET_H
#define RESET_H

#include "command.h"


class XOryxReset
    : public Command
{
public:
    XOryxReset(): t( 0 ) {}
    void execute();

    class Transaction * t;
};


#endif
