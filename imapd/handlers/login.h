#ifndef LOGIN_H
#define LOGIN_H

#include "command.h"
#include "string.h"
#include "sasl/plain.h"


class Login
    : public Command
{
public:
    void parse();
    void execute();

private:
    String n, p;
    Plain *a;
};


#endif
