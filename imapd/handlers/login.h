#ifndef LOGIN_H
#define LOGIN_H

#include "../command.h"

#include <string.h>


class Login: public Command
{
public:
    Login();
    void parse();
    void execute();
private:
    String n, p;
};

#endif
