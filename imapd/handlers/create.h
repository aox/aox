#ifndef CREATE_H
#define CREATE_H

#include "command.h"


class Create
    : public Command
{
public:
    Create();

    void parse();
    void execute();

private:
    String name;
    class Query *q;
};


#endif
