#ifndef SELECT_H
#define SELECT_H

#include "command.h"


class Mailbox;

class Select: public Command {
public:
    Select() { readOnly = false; }

    void parse();
    void execute();

protected:
    bool readOnly;

private:
    String m;
};

class Examine: public Select {
public:
    Examine() { readOnly = true; }
};

#endif
