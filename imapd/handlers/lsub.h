// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LSUB_H
#define LSUB_H

#include "command.h"


class Lsub
    : public Command
{
public:
    void parse();
    void execute();
};


#endif
