#ifndef EVENTLOOP_H
#define EVENTLOOP_H

class Connection;

#include "list.h"


class EventLoop {
public:
    EventLoop();

    void run();
    void step( bool = false );
    void stop();
    void shutdown();
    void addConnection( Connection * );
    void removeConnection( Connection * );
    void closeAllExcept( Connection *, Connection * );
    void flushAll();

    List<Connection> * connections() const;


private:
    class LoopData *d;

    void dispatch( Connection *, bool, bool, int );
};


#endif
