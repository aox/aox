// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef TIMER_H
#define TIMER_H


#include "global.h"


class Timer
    : public Garbage
{
public:
    Timer( class EventHandler *, uint );
    ~Timer();

    bool active() const;
    uint timeout() const;

    class EventHandler * owner();

    void execute();
    void notify();

    void setRepeating( bool );
    bool repeating() const;

private:
    class TimerData * d;
};

#endif
