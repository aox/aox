// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "byteforwarder.h"

#include "scope.h"
#include "log.h"

// struct timeval, fd_set
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
// read, select
#include <unistd.h>
// errno
#include <errno.h>


/*! \class ByteForwarder byteforwarder.h
  The ByteForwarder class forwards all it reads to a sibling forwarder.

  In effect, what one ByteForwarder reads, another reads, and what the
  other reads, the first one writes. Perfect for forwarding data
  between two sockets.

  ByteForwarder is used as a helper for TlsServer.
*/

/*! Constructs an empty ByteForwarder on the file descriptor \a s,
    tied to \a c. When this ByteForwarder is closed, it closes \a c,
    too.

    If \a user is true, the ByteForwarder logs as though it is
    conncted to a client/user. If it is false, it logs as though it is
    connected to tlsproxy.
*/

ByteForwarder::ByteForwarder( int s, Connection * c, bool user )
    : Connection( s, Pipe ), s( 0 ), p( c ), u( user ), eof( false ),
      o( 0 ), l( 0 )
{
    setFirstNonPointer( &u );
}


void ByteForwarder::react( Event e )
{
    if ( !p )
        return;

    switch( e ) {
    case Read:
        setTimeoutAfter( 60 );
        break;

    case Timeout:
        if ( !s )
            ; // we closed. there's no point in doing anything.
        else if ( u )
            log( "No data received from client for 60 seconds",
                 Log::Debug );
        else
            log( "No data received from tlsproxy for 60 seconds",
                 Log::Debug );
        break;

    case Error:
    case Close:
        if ( e == Close ) {
            if ( u ) {
                log( peer().address() + " closed the connection" );
                p->log( "Closing, because " + peer().address() +
                        " closed its connection" );
            }
            else {
                log( "tlsproxy closed the connection" );
                p->log( "Closing connection from " + p->peer().address() +
                        " because tlsproxy closed its connection" );
            }
        }
        else {
            if ( u ) {
                log( peer().address() +
                     ": Unexpected error. Closing connection",
                     Log::Error );
                p->log( "Closing, because tlsproxy closed its connection",
                        Log::Error  );
            }
            else {
                log( "Unexpected error from tlsproxy. Closing connection",
                     Log::Error  );
                p->log( "Closing connection from " + p->peer().address() +
                        " because of a tlsproxy error",
                        Log::Error  );
            }
        }
        close();
        s->close();
        p->close();
        p = 0;
        break;

    case Connect:
    case Shutdown:
        break;
    }
}


/*! Notifies this ByteForwarder (and its old and new siblings) that it
    is to write using \a sibling, or not write at all if \a sibling is
    null.
*/

void ByteForwarder::setSibling( ByteForwarder * sibling )
{
    if ( s == sibling )
        return;

    if ( s )
        s->setSibling( 0 ); // temporarily detach
    s = sibling;
    if ( sibling )
        sibling->setSibling( this );
}


/*! Reads a modest amount of data from the file descriptor. read()
    blocks Connection::read(), and guarantees that the sibling's
    write() will find something to do.
*/

void ByteForwarder::read()
{
    if ( l )
        s->write();
    while ( canRead() ) {
        uint m = 24576 - o - l;
        if ( !m )
            return;

        int r = ::read( fd(), b + o + l, m );
        if ( r > 0 ) {
            l += r;
            s->write();
        }
        else if ( errno == ECONNRESET || r == 0 ) {
            eof = true;
        }
        else if ( r < 0 && ( errno == EAGAIN || errno != EWOULDBLOCK ) ) {
            return;
        }
        else if ( r < 0 ) {
            log( "Read (" + fn( m ) + " bytes) failed with errno " +
                 fn( errno ) );
            close();
            s->close();
            if ( p ) {
                p->log( "Closing due to byteforwarder problem" );
                p->close();
            }
        }
    }
}


/*! Writes the sibling's read buffer, or tries to, and adjusts the
    sibling's read buffer.
*/

void ByteForwarder::write()
{
    if ( !canWrite() )
        return;
    Scope x( log() );
    int r = ::write( fd(), s->b + s->o, s->l );
    if ( r < 0 && errno != EAGAIN && errno != EWOULDBLOCK ) {
        log( "Write (" + fn( s->l ) + " bytes) failed with errno " +
             fn( errno ) );
        close();
        s->close();
        if ( p ) {
            p->log( "Closing due to byteforwarder problem" );
            p->close();
        }
    }
    else if ( r > 0 ) {
        s->l -= r;
        if ( s->l )
            s->o += r;
        else
            s->o = 0;
    }
}


/*! This reimplementation return true as long as the connection is
    valid.
*/

bool ByteForwarder::canRead()
{
    if ( !valid() )
        return false;
    if ( eof )
        return false;
    return true;
}


/*! This reimplementation returns true if the sibling has read
    anything.
*/

bool ByteForwarder::canWrite()
{
    if ( !s )
        return false;
    if ( !s->l )
        return false;
    return true;
}
