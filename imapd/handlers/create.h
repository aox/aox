#ifndef CREATE_H
#define CREATE_H

#include "command.h"


class Create
    : public Command
{
public:
    Create()
        : m( 0 )
    {}

    void parse();
    void execute();

private:
    String name;
    class Mailbox *m;
};


#endif
