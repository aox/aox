// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "consoleloop.h"

#include "scope.h"
#include "loop.h"
#include "connection.h"
#include "log.h"

#include <qapplication.h>

#include <sys/types.h>
#include <sys/socket.h>


WriteNotifier::WriteNotifier( int socket, Connection * connection )
    : QSocketNotifier( socket, Write, 0, 0 ), c( connection )
{
    if ( c->state() == Connection::Connecting )
        setEnabled( true );
    else
        setEnabled( false );
    connect( this, SIGNAL( activated( int ) ),
             this, SLOT( dispatch() ) );
}

void WriteNotifier::dispatch() {
    bool w = true;
    bool r = false;

    if ( c->state() == Connection::Connecting ) {
        int errval;
        int errlen = sizeof( int );
        ::getsockopt( c->fd(), SOL_SOCKET, SO_ERROR, (void *)&errval,
                      (socklen_t *)&errlen );
        if ( errval != 0 )
            r = true;
    }

    Loop::loop()->dispatch( c, r, w, time( 0 ) );
    setEnabled( c->canWrite() &&
                c->state() == Connection::Connected );
}

ReadNotifier::ReadNotifier( int socket, Connection * connection )
    : QSocketNotifier( socket, Read, 0, 0 ), c( connection )
{
    setEnabled( true );
    connect( this, SIGNAL( activated( int ) ),
             this, SLOT( dispatch() ) );
}

void ReadNotifier::dispatch() {
    Loop::loop()->dispatch( c, true, false, time( 0 ) );
}

Connection *ReadNotifier::connection() const
{
    return c;
}

class ConsoleLoopData {
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
    both Qt's and our event loops.
*/

ConsoleLoop::ConsoleLoop()
    : EventLoop(), d( new ConsoleLoopData )
{
    Loop::setup( this );
}


// more than 128 fds in the console is a BUG. we just shouldn't have that.
static const int fdLimit = 128;
static ReadNotifier * r[128];
static WriteNotifier * w[128];


/*! This reimplementation manages \a c using a pair of QSocketNotifier
    objects to do the grunt work
*/

void ConsoleLoop::addConnection( Connection * c )
{
    int fd = c->fd();
    if ( fd >= fdLimit ) {
        ::log( "Too many sockets used", Log::Disaster );
        shutdown();
    }
    r[fd] = new ReadNotifier( fd, c );
    w[fd] = new WriteNotifier( fd, c );
}


/*! Removes \a c from the list of active descriptors. */

void ConsoleLoop::removeConnection( Connection * c )
{
    int fd = c->fd();
    if ( fd >= fdLimit )
        return;

    delete r[fd];
    r[fd] = 0;
    delete w[fd];
    w[fd] = 0;
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
        if ( r[i] ) {
            Connection * c = r[i]->connection();
            Scope x( c->arena() );
            c->react( Connection::Shutdown );
            c->write();
        }
    }
    qApp->exit( 0 );
}
