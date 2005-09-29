// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef THREAD_H
#define THREAD_H

#include "command.h"


class Thread
    : public Command
{
public:
    Thread( bool u );

    void parse();
    void execute();

private:
    class ThreadData * d;
};


#endif
