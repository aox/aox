#ifndef __SEARCH_H__
#define __SEARCH_H__

#include "command.h"


class Search: public Command {
public:
    Search( bool u ): uid( u ) {}

    void parse();
    void execute();

private:
    bool uid;
};

#endif
