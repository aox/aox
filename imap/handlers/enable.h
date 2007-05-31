// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ENABLE_H
#define ENABLE_H

#include "command.h"


class Enable
    : public Command
{
public:
    Enable();

    void parse();
    void execute();

private:
    bool condstore;
    bool annotate;
};


#endif
