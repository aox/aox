#ifndef __CREATE_H__
#define __CREATE_H__

#include "../command.h"

class Create: public Command
{
public:
    void parse();
    void execute();

private:
    String m;
};

#endif
