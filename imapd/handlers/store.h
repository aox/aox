#ifndef __STORE_H__
#define __STORE_H__

#include "command.h"


class Store
    : public Command
{
public:
    void execute();
};

#endif
