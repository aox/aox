// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "consoleloop.h"

#include "connection.h"
#include "allocator.h"
#include "buffer.h"
#include "scope.h"
#include "loop.h"
#include "log.h"

#include <qsocketnotifier.h>
#include <qapplication.h>
#include <qtimer.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>


class ConsoleLoopData
    : public Garbage
{
};


/*! \class ConsoleLoop consoleloop.h

    This class provides a custom event loop which delivers events both
    to Connection objects and QObject ones. The event loop actuallly
    used is QEventLoop (http://doc.trolltech.com/qeventloop.html),
    since Microsoft Windows is incompatible with the select-based
    approach taken by EventLoop. This class reimplements
    addConnection(), removeConnection() and start() to let Qt do all
    their work.
*/


/*! Constructs an event loop for the Mailstore Console, setting up
    both Qt's event loop and our own.
*/

ConsoleLoop::ConsoleLoop()
    : EventLoop(), d( new ConsoleLoopData )
{
    Loop::setup( this );
    Allocator::addEternal( this, "Qt's event loop, and ours too" );
}


// more than 128 fds in the console is a BUG. we just shouldn't have that.
static const int fdLimit = 128;
static EventNotifier * e[128];


/*! This reimplementation manages \a c using a pair of QSocketNotifier
    objects to do the grunt work
*/

void ConsoleLoop::addConnection( Connection * c )
{
    int fd = c->fd();
    if ( fd < 0 ) {
        return;
    }
    else if ( fd >= fdLimit ) {
        ::log( "Too many sockets used", Log::Disaster );
        shutdown();
    }
    e[fd] = new EventNotifier( c );
    Allocator::addEternal( e[fd], "qt/oryx event notifier" );
}


/*! Removes \a c from the list of active descriptors. */

void ConsoleLoop::removeConnection( Connection * c )
{
    int fd = c->fd();
    if ( fd >= fdLimit || fd < 0 )
        return;

    delete e[fd];
    e[fd] = 0;
}


void ConsoleLoop::stop()
{
    qApp->quit();
}


/*! This reimplementation delivers Shutdown events immediately, then
    quits.
*/

void ConsoleLoop::shutdown()
{
    uint i = fdLimit;
    while ( i ) {
        i--;
        if ( e[i] ) {
            Connection * c = e[i]->connection();
            e[i] = 0;
            c->react( Connection::Shutdown );
            c->write();
        }
    }
    qApp->exit( 0 );
}

/*! \class EventNotifier consoleloop.cpp

    This class interfaces QSocketNotifier to EventLoop. Its only real
    function is to merge the read and write notifiers, so EventLoop
    can interpret the combinations correctly. Specifically, when a
    Connection is connecting and the read and write notifiers fire at
    the same time, this can indicate either an succeeding connection
    with outstanding data, or it can indicate an error.
*/


/*! Constructs an EventNotifier interfacing \a connection to the Qt
    event loop. \a connection must be valid, or this object does
    nothing.
*/

EventNotifier::EventNotifier( Connection * connection )
    : QObject( 0 ), rn( 0 ), wn( 0 ), c( connection ), r( false ), w( false )
{
    if ( !c->valid() )
        return;
    rn = new QSocketNotifier( c->fd(), QSocketNotifier::Read, this );
    connect( rn, SIGNAL(activated(int)),
             this, SLOT(acceptRead()) );
    wn = new QSocketNotifier( c->fd(), QSocketNotifier::Write, this );
    connect( wn, SIGNAL(activated(int)),
             this, SLOT(acceptWrite()) );
}


/*! This slot is invoked whenever Qt says a file descriptor is
    readable. It ensures that shortly later, dispatch() is called to
    do its job.
*/

void EventNotifier::acceptRead()
{
    r = true;
    QTimer::singleShot( 0, this, SLOT(dispatch()) );
}


/*! This slot is invoked whenever Qt says a file descriptor is
    writable. It ensures that shortly later, dispatch() is called to
    do its job.
*/

void EventNotifier::acceptWrite()
{
    w = true;
    QTimer::singleShot( 0, this, SLOT(dispatch()) );
}


/*! Uses EventLoop::dispatch() to dispatch the correct mixture of
    read, write, connect and whatever other events need to be sent.
*/

void EventNotifier::dispatch()
{
    bool rr = r;
    bool ww = w;
    r = false;
    w = false;
    Loop::loop()->dispatch( c, rr, ww, time( 0 ) );
    wn->setEnabled( c->state() != Connection::Connected ||
                    c->writeBuffer()->size() > 0 );
}


/*! Returns a pointer to the Connection this EventNotifier looks after. */

Connection * EventNotifier::connection() const
{
    return c;
}
