// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef RESETKEY_H
#define RESETKEY_H

#include "command.h"


class ResetKey
    : public Command
{
public:
    ResetKey();

    void parse();
    void execute();

private:
    String name;
    class Query *q;
};


#endif
