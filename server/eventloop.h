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
    void flushAll();

    void dispatch( Connection *, bool, bool, int );

    bool inStartup() const;
    void setStartup( bool );

    bool signalHandled() const;
    void setSignalHandled( bool );

    List< Connection > *connections() const;

    static void setup( EventLoop * = 0 );
    static EventLoop * global();
    static void shutdown();

private:
    class LoopData *d;
};


#endif
