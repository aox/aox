// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef EVENTLOOP_H
#define EVENTLOOP_H

#include "list.h"


class Connection;


class EventLoop
    : public Garbage
{
public:
    EventLoop();
    virtual ~EventLoop();

    virtual void start();
    virtual void stop();
    virtual void addConnection( Connection * );
    virtual void removeConnection( Connection * );
    void closeAllExcept( Connection *, Connection * );
    void closeAllExceptListeners();
    void flushAll();

    void dispatch( Connection *, bool, bool, uint );

    bool inStartup() const;
    void setStartup( bool );

    bool inShutdown() const;

    List< Connection > *connections() const;

    static void setup( EventLoop * = 0 );
    static EventLoop * global();
    static void shutdown();

    virtual void addTimer( class Timer * );
    virtual void removeTimer( class Timer * );

private:
    class LoopData *d;
};


#endif
