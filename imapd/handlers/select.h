#ifndef __SELECT_H__
#define __SELECT_H__

#include "../command.h"

class Select: public Command
{
public:
    void parse();
    void execute();

private:
    String m;
};

#endif
