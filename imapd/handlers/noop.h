#ifndef NOOP_H
#define NOOP_H

#include "command.h"


class Noop
    : public Command
{
public:
    Noop()
        : q( 0 ), n( 0 )
    {}
    void execute();

private:
    class Query *q;
    int n;
};

#endif
