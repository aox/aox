// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "loop.h"

#include "eventloop.h"
#include "allocator.h"


static EventLoop * loop;


/*! \class Loop loop.h
    The program's global event loop.

    This class is a wrapper that provides static methods to manipulate a
    single global EventLoop object. It used to be the event loop itself,
    until we needed multiple event loops, especially during startup.

    Should we get rid of this class and store the current Loop in
    Scope? A resounding yes from arnt, and a no.
*/

/*! Creates the global EventLoop object, or uses one supplied by the
    caller, \a l.  This function expects to be called by ::main().
*/

void Loop::setup( EventLoop * l )
{
    ::loop = l;
    if ( !l )
        ::loop = new EventLoop;
    Allocator::addEternal( ::loop, "main event loop" );
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


/*! Kills all the Connection objects except \a c1 and \a c2 brutally,
    without flushing their buffers. Used for TlsProxy.
*/

void Loop::closeAllExcept( Connection * c1, Connection * c2 )
{
    if ( ::loop )
        ::loop->closeAllExcept( c1, c2 );
}


/*! Flushes the write buffer for all connections. */

void Loop::flushAll()
{
    if ( ::loop )
        ::loop->flushAll();
}


/*! Returns a (non-zero) pointer to the list of connections in the
    global Loop.
*/

List< Connection > *Loop::connections()
{
    List< Connection > *l = 0;
    if ( ::loop )
        l = ::loop->connections();
    else
        l = new List< Connection >;
    return l;
}


/*! Returns a pointer to the global event loop, or a null pointer if
    there isn't any.
*/

EventLoop * Loop::loop()
{
    return ::loop;
}
