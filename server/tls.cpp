#include "tls.h"

#include "connection.h"
#include "string.h"
#include "configuration.h"
#include "buffer.h"

// socketpair
#include <sys/types.h>
#include <sys/socket.h>
// fork, execl
#include <unistd.h>
// waitpid
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
// exit
#include <stdlib.h>


class TlsServerData
{
public:
    TlsServerData(): handler( 0 ), done( false ), ok( false ) {
        userside[0] = -1;
        userside[1] = -1;
        serverside[0] = -1;
        serverside[1] = -1;
        control[0] = -1;
        control[1] = -1;
    }

    EventHandler * handler;
    int userside[2];
    int serverside[2];
    int control[2];
    bool done;
    bool ok;

    class Client: public Connection
    {
    public:
        Client( int, TlsServerData * );
        void react( Event );

        class TlsServerData * d;
    };
};


TlsServerData::Client::Client( int fd, TlsServerData * data )
    : Connection( fd, Connection::Client ), d( data )
{
}


void TlsServerData::Client::react( Event e )
{
    if ( e == Read ) {
        String * s = readBuffer()->removeLine();
        if ( s ) {
            String l = s->simplified();
            if ( l == "ok" ) {
                d->done = true;
                d->ok = true;
            }
            else {
                d->done = true;
                d->ok = false;
            }
        }
    }
    else if ( e != Connect ) {
        if ( !d->done ) {
            d->done = true;
            d->ok = false;
        }
    }
}


/*! \class TlsServer tls.h
  The TlsServer class provides an interface to server-side TLS.

  On construction, it forks and executes a TlsProxy, and eventually
  verifies that the proxy is available to work as a server. Once its
  availability has been probed, done() returns true and ok() returns
  either a meaningful result.
*/


/*! Constructs a TlsServer and starts setting up the proxy server. It
    returns quickly, and later notifies \a handler when setup as
    compleed.
*/

TlsServer::TlsServer( EventHandler * handler )
    : d( new TlsServerData )
{
    d->handler = handler;

    if ( socketpair( AF_UNIX, SOCK_STREAM, 0, d->userside ) < 0 ||
         socketpair( AF_UNIX, SOCK_STREAM, 0, d->serverside ) < 0 ||
         socketpair( AF_UNIX, SOCK_STREAM, 0, d->control ) < 0 ) {
        d->done = true;
        return;
    }

    int p1 = fork();
    if ( p1 < 0 ) {
        d->done = true;
        return;
    }

    if ( p1 > 0 )
        parent( p1 );
    else
        intermediate();
}


/*! This private helper performs all parent-related tasks. */

void TlsServer::parent( int wpid )
{
    ::close( d->userside[1] );
    ::close( d->serverside[1] );
    ::close( d->control[1] );
    int status = 0;
    waitpid( wpid, &status, WNOHANG ); // we'll have a zombie if shit happens
}


/*! This private function implements the short-lived bounce
    process. That process exists only so that the TLS proxy will not
    need to be waited upon by the running servers.
*/

void TlsServer::intermediate()
{
    int p2 = fork();
    if ( p2 == 0 )
        child();
    if ( p2 < 0 )
        bad();
    exit( 0 );
}


/*! This privat helpers implements all that must be done in the child
    in order to start the TLS proxy.
*/

void TlsServer::child()
{
    int s = getdtablesize();
    while ( s > 0 ) {
        s--;
        if ( s == d->userside[1] ||
             s == d->serverside[1] ||
             s == d->control[1] ) {
            // we leave those three alone
        } else {
            close( s );
        }
    }
    String userside = String::fromNumber( d->userside[1] );
    String serverside = String::fromNumber( d->userside[1] );
    String control = String::fromNumber( d->userside[1] );
    String tlsproxy = Configuration::compiledIn( Configuration::BinDir );
    tlsproxy.append( "/tlsproxy" );
    (void)execl( tlsproxy.cstr(),
                 "tlsproxy",
                 "server",
                 userside.cstr(),
                 serverside.cstr(),
                 control.cstr(),
                 0 );
    bad();
    exit( 0 );
}


/*! Notifies the parent process that something isn't at all good. */

void TlsServer::bad()
{
    ::write( d->control[1], "bad\n", 4 );
}


/*! Returns true if setup has finished, and false if it's still going on. */

bool TlsServer::done() const
{
    return d->done;
}


/*! Returns true if the TLS proxy is available for use, and false is
    an error happened or setup is still going on.
*/

bool TlsServer::ok() const
{
    return d->done && d->ok;
}


/*! Returns the file descriptor which talks to the user side
    (encrypted side) of the TLS proxy. If an error occured during
    setup, this function returns -1.
*/

int TlsServer::userSideSocket() const
{
    if ( !ok() )
        return -1;

    return d->userside[0];
}


/*! Returns the file descriptor which talks to the server side
    (cleartext side) of the TLS proxy. If an error occured during
    setup, this function returns -1.
*/

int TlsServer::serverSideSocket() const
{
    if ( !ok() )
        return -1;

    return d->serverside[0];
}
