#include "pop3.h"

#include "string.h"
#include "buffer.h"
#include "log.h"


class PopData {
public:
    PopData()
        : state( POP3::Authorization )
    {}

    POP3::State state;
};


/*! \class POP3 pop3.h
    This class implements a POP3 server.

    The Post Office Protocol is defined by RFC 1939, and updated by RFCs
    1957 (which doesn't say much) and 2449, which defines CAPA and other
    extensions. RFC 1734 defines an AUTH command for SASL authentication
    support, and RFC 2595 defines STARTTLS for POP3.
*/

/*! Creates a POP3 server for the fd \a s, and sends the initial banner.
*/

POP3::POP3( int s )
    : Connection( s, Connection::Pop3Server ),
      d( new PopData )
{
    ok( "POP3 server ready." );
    setTimeoutAfter( 600 );
}


/*! \reimp */

POP3::~POP3()
{
}


/*! Sets this server's state to \a s, which may be one of Authorization,
    Transaction, or Update (as defined in POP3::State).
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
        setTimeoutAfter( 600 );
        parse();
        break;

    case Timeout:
        // May we send a response here?
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
    Buffer *b = readBuffer();

    while ( b->size() > 0 ) {
        String *s = b->removeLine( 255 );

        if ( !s ) {
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
        
        if ( cmd == "quit" && args.isEmpty() ) {
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
            unknown = true;
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

void POP3::ok( const String &s )
{
    enqueue( "+OK " + s + "\r\n" );
}


/*! Sends \a s as a negative -ERR response. */

void POP3::err( const String &s )
{
    enqueue( "-ERR " + s + "\r\n" );
}
