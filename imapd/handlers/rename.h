#ifndef __RENAME_H__
#define __RENAME_H__

#include "../command.h"

class Rename: public Command
{
public:
    void parse();
    void execute();

private:
    String a, b;
};

#endif
