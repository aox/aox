#ifndef RENAME_H
#define RENAME_H

#include "command.h"


class Rename: public Command {
public:
    void parse();
    void execute();

private:
    String a, b;
};

#endif
