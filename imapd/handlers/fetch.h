#ifndef __FETCH_H__
#define __FETCH_H__

#include "command.h"


class Fetch: public Command {
public:
    Fetch( bool u ): uid( u ) {}

    void parse();
    void execute();

private:
    bool uid;
};

#endif
