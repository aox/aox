#ifndef CAPABILITY_H
#define CAPABILITY_H

#include "../command.h"


class Capability: public Command
{
public:
    Capability();
    ~Capability();

    void execute();
};

#endif
