// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IDLE_H
#define IDLE_H

#include "command.h"


class Idle
    : public Command
{
public:
    void execute();
    void read();
};


#endif
