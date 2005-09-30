// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef THREAD_H
#define THREAD_H

#include "search.h"


class Thread
    : public Search
{
public:
    Thread( bool u );

    void parse();
    void execute();
    void process();

private:
    class ThreadData * d;
};


#endif
