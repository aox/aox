#include "event.h"

#include "arena.h"
#include "scope.h"


class DCData {
public:
    DCData()
        : arena( 0 )
    {}

    Arena *arena;
};


/*! \class EventHandler event.h
    This is a base class for anything that needs to Query the Database.

    XXX: This class is poorly named. It is actually a base class for any
    objects that need to be notified of external events. Rename it when
    we think of a better name.
*/


/*! Creates a new EventHandler object.
*/

EventHandler::EventHandler()
    : d( new DCData )
{
}


/*! Returns this object's arena.
    execute() expects this arena to be current before it is called.
*/

Arena *EventHandler::arena() const
{
    return d->arena;
}


/*! Sets this object's Arena to \a a.
*/

void EventHandler::setArena( Arena *a )
{
    d->arena = a;
}


/*! \fn void EventHandler::execute()

    This pure virtual function is called by Query::notify() when there's
    something the client needs to do to process the Query.
*/


/*! This function sets the correct arena() and calls execute().
*/

void EventHandler::notify()
{
    Scope x( d->arena );
    execute();
}
