#ifndef CONSOLELOOP_H
#define CONSOLELOOP_H

#include "eventloop.h"


class ConsoleLoop: public EventLoop
{
public:
    ConsoleLoop();

    void stop();
    void shutdown();
    void addConnection( Connection * c );
    void removeConnection( Connection * );

private:
    class ConsoleLoopData * d;
};



#endif
