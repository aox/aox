#include "loop.h"

#include "arena.h"
#include "scope.h"
#include "eventloop.h"


static EventLoop *loop;


/*! \class Loop loop.h
    The program's global event loop.

    This class is a wrapper that provides static methods to manipulate a
    single global EventLoop object. It used to be the event loop itself,
    until we needed multiple event loops, especially during startup.

    Should we get rid of this class and store the current Loop in Scope?
*/

/*! Creates the global EventLoop object.
    This function expects to be called by ::main().
*/

void Loop::setup()
{
    ::loop = new EventLoop;
}


/*! Calls EventLoop::start() on the global EventLoop object. */

void Loop::start()
{
    ::loop->start();
}


/*! Calls EventLoop::shutdown() on the global EventLoop object. */

void Loop::shutdown()
{
    ::loop->shutdown();
}


/*! Calls EventLoop::addConnection( \a c ) on the global EventLoop
    object.
*/

void Loop::addConnection( Connection *c )
{
    if ( ::loop )
        ::loop->addConnection( c );
}


/*! Calls EventLoop::removeConnection( \a c ) on the global EventLoop
    object.
*/

void Loop::removeConnection( Connection *c )
{
    if ( ::loop )
        ::loop->removeConnection( c );
}


/*!

*/

void Loop::killAllExcept( Connection * c1, Connection * c2 )
{
    if ( ::loop )
        ::loop->killAllExcept( c1, c2 );
}
