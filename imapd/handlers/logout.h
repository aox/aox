#ifndef LOGOUT_H
#define LOGOUT_H

#include "command.h"


class Logout: public Command {
public:
    Logout();
    ~Logout();

    void execute();
};

#endif
