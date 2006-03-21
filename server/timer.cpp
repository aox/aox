// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "timer.h"

#include "event.h"
#include "eventloop.h"

// time
#include <time.h>


class TimerData
    : public Garbage
{
public:
    EventHandler * owner;
    uint timeout;
};


/*! \class Timer timer.h

    The Timer class provides a way to ask for a callback at a time of
    your chooring, or a little later.

    The class provides second resolution, nothing better.
*/


/*!  Constructs an timer which will notify \a owner after \a delay
     seconds, or slightly more.
*/

Timer::Timer( class EventHandler * owner, uint delay )
    : Garbage(), d( new TimerData )
{
    uint now = time( 0 );
    if ( delay + now < now )
        return; // would be after the end of the universe...
    d->owner = owner;
    d->timeout = delay + now;
    EventLoop::global()->addTimer( this );
}


/*! Requests that owner() not be notified. Any recorded timeout is
    forgotten.
*/

Timer::~Timer()
{
    EventLoop::global()->removeTimer( this );
}


/*! Returns true if this timer will call the EventHandler::execute()
    function of owner() at some point, and falls if it will not.

    In particular, if it is presently calling EventHandler::execute(),
    it will not do it again in the future, so it returns false.
*/

bool Timer::active() const
{
    if ( d->timeout )
        return true;
    return false;
}


/*! Returns the time (as an integer number of seconds increasing
    towards the future) at which this Timer will call
    EventHandler::execute(), or 0 if it is not active().
*/

uint Timer::timeout() const
{
    return d->timeout;
}


/*! Returns a pointer to the the EventHandler object that this Timer
    will notify.
*/

class EventHandler * Timer::owner()
{
    return d->owner;
}
