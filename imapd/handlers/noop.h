#ifndef NOOP_H
#define NOOP_H

#include "command.h"


class Noop: public Command {
public:
    void execute();
};

#endif
