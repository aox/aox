#ifndef EXPUNGE_H
#define EXPUNGE_H

#include "command.h"


class Expunge: public Command {
public:
    void execute();

    void expunge( bool );
};

#endif
