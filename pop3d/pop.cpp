// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "pop.h"

#include "log.h"
#include "string.h"
#include "buffer.h"
#include "eventloop.h"
#include "popcommand.h"
#include "stringlist.h"


class PopData
    : public Garbage
{
public:
    PopData()
        : state( POP::Authorization ), sawUser( false ),
          commands( new List< PopCommand > )
    {}

    POP::State state;

    bool sawUser;
    String user;
    String pass;

    List< PopCommand > * commands;
};


static void newCommand( List< PopCommand > *, POP *,
                        PopCommand::Command, StringList * = 0 );


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

        bool unknown = false;

        StringList * args = StringList::split( ' ', *s );
        String cmd = args->take( args->first() )->lower();

        if ( d->sawUser && !( cmd == "quit" || cmd == "pass" ) ) {
            d->sawUser = false;
            unknown = true;
        }
        else if ( cmd == "quit" && args->isEmpty() ) {
            newCommand( d->commands, this, PopCommand::Quit );
        }
        else if ( cmd == "capa" && args->isEmpty() ) {
            newCommand( d->commands, this, PopCommand::Capa );
        }
        else if ( d->state == Authorization ) {
            if ( cmd == "user" && args->count() == 1 ) {
                d->sawUser = true;
                newCommand( d->commands, this, PopCommand::User, args );
            }
            else if ( d->sawUser && cmd == "pass" && args->count() == 1 ) {
                d->sawUser = false;
                newCommand( d->commands, this, PopCommand::Pass, args );
            }
            else {
                unknown = true;
            }
        }
        else if ( d->state == Transaction ) {
            if ( cmd == "noop" && args->isEmpty() ) {
                newCommand( d->commands, this, PopCommand::Noop );
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

        runCommands();
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


/*! The POP server maintains a list of commands received from the
    client and processes them one at a time in the order they were
    received. This function executes the first command in the list,
    or if the first command has completed, removes it and executes
    the next one.

    It should be called when a new command has been created (i.e.,
    by POP::parse()) or when a running command finishes.
*/

void POP::runCommands()
{
    List< PopCommand >::Iterator it( d->commands );
    if ( !it )
        return;
    if ( it->done() )
        d->commands->take( it );
    if ( it )
        it->execute();
}


static void newCommand( List< PopCommand > * l, POP * pop,
                        PopCommand::Command cmd,
                        StringList * args )
{
    l->append( new PopCommand( pop, cmd, args ) );
}


/*! Sets the current user of this POP server to \a s. Called upon
    receipt of a valid USER command.
*/

void POP::setUser( const String &s )
{
    d->user = s;
}


/*! Returns the current user of this POP server, or an empty string if
    setUser() has never been called upon receipt of a USER command.
*/

String POP::user() const
{
    return d->user;
}
