#ifndef APPEND_H
#define APPEND_H

#include "command.h"


class Append
    : public Command
{
public:
    Append();

    void parse();
    void execute();

private:
    uint number( uint );

    class AppendData * d;
};


#endif
