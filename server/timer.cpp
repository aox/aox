// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "timer.h"

#include "event.h"
#include "eventloop.h"
#include "connection.h"
#include "scope.h"

// time
#include <time.h>


class TimerData
    : public Garbage
{
public:
    TimerData(): owner( 0 ), timeout( 0 ), interval( 0 ), repeating( false ) {}
    EventHandler * owner;
    uint timeout;
    uint interval;
    bool repeating;
};


/*! \class Timer timer.h

    The Timer class provides a way to ask for one callback at a time
    of your choosing, or for regular callbacks at a specified
    intervals. The default is one callback; calling setRepeating()
    changes that.

    The class provides second resolution, nothing better. Creating a
    timer with delay/interval of 1 provides the first callback after
    1-2 seconds and (if repeating() is true) at 1-second intervals
    thereafter.

    If the system is badly overloaded, callbacks may be skipped. There
    never is more than one activation pending for a single Timer.
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
    d->interval = delay;
    EventLoop::global()->addTimer( this );
}


/*! Kills this timer right now, preventing any future callbacks. */

Timer::~Timer()
{
    EventLoop::global()->removeTimer( this );
}


/*! Returns true if this timer will call the EventHandler::execute()
    function of owner() at some point, and falls if it will not.

    In particular, if it is presently calling EventHandler::execute()
    and will not do it again in the future, so it returns false.
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


/*! Called by the EventLoop when this Timer should notify its owner(). */

void Timer::execute()
{
    if ( d->repeating ) {
        d->timeout += d->interval;
        uint now = time( 0 );
        // if we can't make the required frequency, get as close as we can
        if ( d->timeout <= now )
            d->timeout = now + 1;
    }
    else {
        d->timeout = 0;
        EventLoop::global()->removeTimer( this );
    }

    notify();
}


/*! This function notifies the owner of this Timer's expiration. */

void Timer::notify()
{
    if ( !d->owner )
        return;

    // XXX: This is a copy of code in Query::notify() and
    // Transaction::notify(). We need to fix this properly.

    Scope s( d->owner->log() );
    try {
        d->owner->execute();
    }
    catch ( const Exception& e ) {
        d->owner = 0; // so we can't get close to a segfault again
        if ( e == Invariant ) {
            // Analogous to EventLoop::dispatch, we try to close the
            // connection that threw the exception. The problem is
            // that we don't know which one did. So we try to find one
            // whose Log object is an ancestor of this query's owner's
            // Log object.

            List<Connection>::Iterator i( EventLoop::global()->connections() );
            while ( i ) {
                Connection * c = i;
                ++i;
                Log * l = Scope::current()->log();
                while ( l && l != c->log() )
                    l = l->parent();
                if ( c->type() != Connection::Listener && l ) {
                    Scope x( l );
                    ::log( "Invariant failed; Closing connection abruptly",
                           Log::Error );
                    EventLoop::global()->removeConnection( c );
                    c->close();
                }
            }
        }
        else {
            throw;
        }
    }
}


/*! Makes this Timer notify its owner at regular intervals if \a r is
    true, and just once (more) if \a r is false.

    The initial value is false. If you call setRepeating( false ) on
    an existing timer, it will be executed once more and then be
    freed.
*/

void Timer::setRepeating( bool r )
{
    d->repeating = r;
}


/*! Returns true if this Timer will notify its owner at regular
    intervals, and false if it notifies its owner just once. The
    initial value is false.
*/

bool Timer::repeating() const
{
    return d->repeating;
}
