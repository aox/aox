#ifndef __IDLE_H__
#define __IDLE_H__

#include "command.h"


class Idle: public Command {
public:
    void execute();
    void read();
};

#endif
