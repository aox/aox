#ifndef __LOGIN_H__
#define __LOGIN_H__

#include "command.h"
#include "string.h"


class Login: public Command {
public:
    Login();
    void parse();
    void execute();

private:
    String n, p;
};

#endif
