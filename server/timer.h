// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef TIMER_H
#define TIMER_H


#include "global.h"


class Timer
    : public Garbage
{
public:
    Timer( class EventHandler *, uint );

    bool active() const;
    uint timeout() const;

    class EventHandler * owner();

    void execute();

    void setRepeating( bool );
    bool repeating() const;

private:
    class TimerData * d;
};

#endif
