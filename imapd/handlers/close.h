#ifndef CLOSE_H
#define CLOSE_H

#include "expunge.h"


class Close: public Expunge {
public:
    void execute();
};

#endif
