// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOGOUT_H
#define LOGOUT_H

#include "command.h"


class Logout
    : public Command
{
public:
    void execute();
};


#endif
