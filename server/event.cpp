// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "event.h"

#include "arena.h"
#include "scope.h"


/*! \class EventHandler event.h
    An abstract base class for anything that wants event notifications.

    Classes that want to be notified of events (e.g. the completion of
    a database query) must inherit from EventHandler and implement the
    execute() function, and may also provide an arena() for its use.

    Objects of that class may then pass their "this" pointers to code
    that promises to notify() them of events. When the event occurs,
    notify() calls execute() with the correct arena() set.

    There is currently no way to indicate the type or originator of an
    event. Furthermore, the Loop/Connection framework uses an entirely
    different scheme for event notifications.
*/


/*! Creates a new EventHandler object, and sets its arena to the current
    arena.
*/

EventHandler::EventHandler()
{
    a = Scope::current()->arena();
    l = Scope::current()->log();
}


/*! Returns this object's arena. This arena must be current before
    execute() is called.
*/

Arena *EventHandler::arena() const
{
    return a;
}


/*! Sets this object's Arena to \a arena.
*/

void EventHandler::setArena( Arena *arena )
{
    a = arena;
}


/*! Sets this object's Log to \a log.
*/

void EventHandler::setLog( Log *log )
{
    l = log;
}


/*! This function calls execute() with the correct arena().
*/

void EventHandler::notify()
{
    Scope x( a );
    execute();
}


/*! \fn void EventHandler::execute()

    This pure virtual function is called by notify() when there's
    something the EventHandler needs to do to process an event.
*/


/*! Logs the message \a m with severity \a s using this EventHandler's
    Log, as specified with setLog().
*/

void EventHandler::log( const String &m, Log::Severity s )
{
    if ( l )
        l->log( m, s );
}


/*! Commits any messages logged with severity above \a s. */

void EventHandler::commit( Log::Severity s )
{
    if ( l )
        l->commit( s );
}
