// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef EVENTLOOP_H
#define EVENTLOOP_H

class Connection;

#include "list.h"


class EventLoop {
public:
    EventLoop();

    virtual void start();
    virtual void stop();
    virtual void shutdown();
    virtual void addConnection( Connection * );
    virtual void removeConnection( Connection * );
    void closeAllExcept( Connection *, Connection * );
    void flushAll();
    
    void dispatch( Connection *, bool, bool, int );

private:
    class LoopData *d;
};


#endif
