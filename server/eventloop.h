#ifndef EVENTLOOP_H
#define EVENTLOOP_H

class Connection;


class EventLoop {
public:
    EventLoop();

    void start();
    void stop();
    void shutdown();
    void addConnection( Connection * );
    void removeConnection( Connection * );
    void closeAllExcept( Connection *, Connection * );
    void flushAll();

private:
    class LoopData *d;

    void dispatch( Connection *, bool, bool, int );
};


#endif
