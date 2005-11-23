// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "pop.h"

#include "string.h"
#include "buffer.h"
#include "eventloop.h"
#include "log.h"


class PopData
    : public Garbage
{
public:
    PopData()
        : state( POP::Authorization ), sawUser( false )
    {}

    POP::State state;

    bool sawUser;
    String user;
    String pass;
};


/*! \class POP3 pop.h
    This class implements a POP3 server.

    The Post Office Protocol is defined by RFC 1939, and updated by RFCs
    1957 (which doesn't say much) and 2449, which defines CAPA and other
    extensions. RFC 1734 defines an AUTH command for SASL authentication
    support, and RFC 2595 defines STARTTLS for POP3.
*/

/*! Creates a POP3 server for the fd \a s, and sends the initial banner.
*/

POP::POP( int s )
    : Connection( s, Connection::Pop3Server ),
      d( new PopData )
{
    ok( "POP3 server ready." );
    setTimeoutAfter( 600 );
    EventLoop::global()->addConnection( this );
}


/*! Sets this server's state to \a s, which may be one of Authorization,
    Transaction, or Update (as defined in POP3::State).
*/

void POP::setState( State s )
{
    d->state = s;
}


/*! Returns the server's current state. */

POP::State POP::state() const
{
    return d->state;
}


void POP::react( Event e )
{
    switch ( e ) {
    case Read:
        setTimeoutAfter( 600 );
        parse();
        break;

    case Timeout:
        // We may not send any response.
        log( "Idle timeout" );
        Connection::setState( Closing );
        break;

    case Connect:
    case Error:
    case Close:
        break;

    case Shutdown:
        // RFC1939 says that if the server times out, it should close
        // silently. It doesn't talk about server shutdown, so it
        // sounds sensible to do nothing in that case as well.
        break;
    }

    if ( d->state == Update )
        Connection::setState( Closing );
    commit();
}


/*! Parses POP3 client commands. */

void POP::parse()
{
    Buffer *b = readBuffer();

    while ( b->size() > 0 ) {
        String *s = b->removeLine( 255 );

        if ( !s ) {
            log( "Connection closed due to overlong line (" +
                 fn( b->size() ) + " bytes)", Log::Error );
            err( "Line too long. Closing connection." );
            Connection::setState( Closing );
            return;
        }

        String cmd, args;

        int n = s->find( ' ' );
        if ( n < 0 ) {
            cmd = *s;
        }
        else {
            cmd = s->mid( 0, n ).lower();
            args = s->mid( n );
        }

        bool unknown = false;

        if ( d->sawUser && ( cmd != "quit" && cmd != "pass" ) ) {
            d->sawUser = false;
            unknown = true;
        }
        else if ( cmd == "quit" && args.isEmpty() ) {
            log( "Closing connection due to QUIT command", Log::Debug );
            ok( "Goodbye" );
            setState( Update );
        }
        else if ( cmd == "capa" && args.isEmpty() ) {
            // We make no attempt here to use the capabilities defined
            // in imapd/handlers/capability.cpp.
            ok( "Supported capabilities:" );
            enqueue( "USER\r\n" );
            enqueue( "RESP-CODES\r\n" );
            enqueue( "PIPELINING\r\n" );
            enqueue( "IMPLEMENTATION Oryx POP3 Server.\r\n" );
            enqueue( ".\r\n" );
        }
        else if ( d->state == Authorization ) {
            if ( cmd == "user" && !args.isEmpty() ) {
                d->sawUser = true;
                d->user = args.mid( 1 );
                ok( "Send PASS." );
            }
            else if ( d->sawUser && cmd == "pass" && !args.isEmpty() ) {
                d->sawUser = false;
                d->pass = args.mid( 1 );
                err( "Authentication failed." );
            }
            else {
                unknown = true;
            }
        }
        else if ( d->state == Transaction ) {
            if ( cmd == "noop" && args.isEmpty() ) {
                ok( "Done." );
            }
            else {
                unknown = true;
            }
        }
        else {
            unknown = true;
        }

        if ( unknown )
            err( "Bad command." );
    }
}


/*! Sends \a s as a positive +OK response. */

void POP::ok( const String &s )
{
    enqueue( "+OK " + s + "\r\n" );
}


/*! Sends \a s as a negative -ERR response. */

void POP::err( const String &s )
{
    enqueue( "-ERR " + s + "\r\n" );
}
