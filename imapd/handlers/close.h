#ifndef __CLOSE_H__
#define __CLOSE_H__

#include "expunge.h"


class Close: public Expunge {
public:
    void execute();
};

#endif
