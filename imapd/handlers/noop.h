#ifndef NOOP_H
#define NOOP_H

#include "../command.h"


class Noop: public Command
{
public:
    Noop();
    ~Noop();

    void execute();
};


#endif
