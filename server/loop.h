#ifndef LOOP_H
#define LOOP_H

class Connection;
class EventLoop;

#include "list.h"


class Loop {
public:
    static void setup( EventLoop * = 0 );
    static void start();
    static void shutdown();
    static void addConnection( Connection * );
    static void removeConnection( Connection * );
    static void closeAllExcept( Connection *, Connection * );
    static void flushAll();

    static EventLoop * loop();
};


#endif
