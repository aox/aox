#ifndef IDLE_H
#define IDLE_H

#include "../command.h"


class Idle: public Command
{
public:
    Idle();
    void execute();
    void read();
};

#endif
