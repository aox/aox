#ifndef CREATE_H
#define CREATE_H

#include "command.h"


class Create: public Command {
public:
    void parse();
    void execute();

private:
    String m;
};

#endif
