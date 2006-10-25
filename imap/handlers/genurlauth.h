// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef GENURLAUTH_H
#define GENURLAUTH_H

#include "command.h"


class GenUrlauth
    : public Command
{
public:
    GenUrlauth();

    void parse();
    void execute();

private:
    class GenUrlauthData *d;
};


#endif
