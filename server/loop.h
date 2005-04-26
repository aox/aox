// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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

    static List< Connection > *connections();
    static EventLoop * loop();
};


#endif
