#include "pop3.h"

#include "string.h"
#include "buffer.h"
#include "log.h"

#include <time.h>


class PopData {
public:
    PopData()
        : state( POP3::Authorization )
    {}

    POP3::State state;
};


/*! \class POP3 pop3.h
    Implements a POP3 server.

    The Post Office Protocol is described in RFC 1939, as updated by RFC
    1957 and 2449. RFC 1734 describes the AUTH mechanism, while RFC 2595
    defines STARTTLS for POP3.
*/

/*! Creates a POP3 server object for the fd \a s. */

POP3::POP3( int s )
    : Connection( s, Connection::Pop3Server ),
      d( new PopData )
{
    ok( "POP3" );
    setTimeout( time(0) + 600 );
}


/*! \reimp */

POP3::~POP3()
{
}


/*! Sets the server's state to \a s, which may be any of:
*/

void POP3::setState( State s )
{
    d->state = s;
}


/*! Returns the server's current state. */

POP3::State POP3::state() const
{
    return d->state;
}


/*! \reimp */

void POP3::react( Event e )
{
    switch ( e ) {
    case Read:
        setTimeout( time(0) + 600 );
        parse();
        break;

    case Timeout:
        Connection::setState( Closing );
        break;

    case Connect:
    case Error:
    case Close:
        log( "Unexpected close by client." );
        break;

    case Shutdown:
        // Should we do something else here?
        Connection::setState( Closing );
        break;
    }

    if ( d->state == Update )
        Connection::setState( Closing );
}


/*! Parses POP3 client commands. */

void POP3::parse()
{
    String *s;

    while ( ( s = readBuffer()->removeLine() ) != 0 ) {
        String cmd;
        String args;

        int n = s->find( ' ' );
        if ( n < 0 ) {
            cmd = *s;
        }
        else {
            cmd = s->mid( 0, n ).lower();
            args = s->mid( n );
        }

        if ( cmd == "quit" )
            quit();
        else
            err( "Bad command" );
    }
}


/*! Sends \a s as a positive +OK response. */

void POP3::ok( const String &s )
{
    enqueue( "+OK " + s + "\r\n" );
}


/*! Sends \a s as a negative -ERR response. */

void POP3::err( const String &s )
{
    enqueue( "-ERR " + s + "\r\n" );
}


/*! Handles the QUIT command. */

void POP3::quit()
{
    ok( "Goodbye" );
    setState( Update );
}
