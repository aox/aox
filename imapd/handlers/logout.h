#ifndef __LOGOUT_H__
#define __LOGOUT_H__

#include "command.h"


class Logout: public Command {
public:
    Logout();
    ~Logout();

    void execute();
};

#endif
