#ifndef __EXPUNGE_H__
#define __EXPUNGE_H__

#include "command.h"


class Expunge: public Command {
public:
    void execute();

    void expunge( bool );
};

#endif
