#ifndef __ID_H__
#define __ID_H__

#include "command.h"


class Id: public Command {
public:
    void parse();
    void execute();
};

#endif
