#ifndef SUBSCRIBE_H
#define SUBSCRIBE_H

#include "command.h"


class Subscribe: public Command {
public:
    void parse();
    void execute();

private:
    String m;
};

#endif
