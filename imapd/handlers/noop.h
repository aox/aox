#ifndef __NOOP_H__
#define __NOOP_H__

#include "command.h"


class Noop: public Command {
public:
    void execute();
};

#endif
