// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOGIN_H
#define LOGIN_H

#include "command.h"
#include "string.h"
#include "plain.h"


class Login
    : public Command
{
public:
    Login();

    void parse();
    void execute();

private:
    String n, p;
    Plain *m;
};


#endif
