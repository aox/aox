#ifndef STATUS_H
#define STATUS_H

#include "command.h"


class Status
    : public Command
{
public:
    void parse();
    void execute();
};


#endif
