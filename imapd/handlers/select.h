#ifndef SELECT_H
#define SELECT_H

#include "command.h"


class Select
    : public Command
{
public:
    Select( bool = false );

    void parse();
    void execute();

private:
    String name;
    bool readOnly;
    class Mailbox *m;
};


class Examine
    : public Select
{
public:
    Examine();
};


#endif
