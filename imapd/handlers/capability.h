#ifndef __CAPABILITY_H__
#define __CAPABILITY_H__

#include "command.h"


class Capability: public Command {
public:
    Capability();
    ~Capability();

    void execute();

    static const char * capabilities();
};

#endif
