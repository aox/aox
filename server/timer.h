// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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

private:
    class TimerData * d;
};

#endif
