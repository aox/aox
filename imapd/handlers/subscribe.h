#ifndef __SUBSCRIBE_H__
#define __SUBSCRIBE_H__

#include "command.h"


class Subscribe: public Command {
public:
    void parse();
    void execute();

private:
    String m;
};

#endif
