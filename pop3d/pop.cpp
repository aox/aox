// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "pop.h"

#include "log.h"
#include "user.h"
#include "string.h"
#include "buffer.h"
#include "session.h"
#include "eventloop.h"
#include "popcommand.h"
#include "stringlist.h"
#include "configuration.h"


class PopData
    : public Garbage
{
public:
    PopData()
        : state( POP::Authorization ), sawUser( false ), user( 0 ),
          commands( new List< PopCommand > ), reader( 0 ),
          reserved( false ), session( 0 )
    {}

    POP::State state;

    bool sawUser;
    User * user;

    List< PopCommand > * commands;
    PopCommand * reader;
    bool reserved;
    Session * session;
};


static bool allowPlaintext = true;
static bool supportsPlain = true;
static bool supportsCramMd5 = true;
static bool supportsDigestMd5 = true;
static bool supportsAnonymous = true;


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
        if ( !d->reader ) {
            if ( d->reserved )
                break;

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
                if ( cmd == "stls" ) {
                    if ( hasTls() )
                        err( "Nested STLS" );
                    else
                        newCommand( d->commands, this, PopCommand::Stls );
                }
                else if ( cmd == "auth" ) {
                    newCommand( d->commands, this, PopCommand::Auth, args );
                }
                else if ( cmd == "user" && args->count() == 1 ) {
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
                if ( cmd == "stat" && args->isEmpty() ) {
                    newCommand( d->commands, this, PopCommand::Stat );
                }
                else if ( cmd == "list" ) {
                    newCommand( d->commands, this, PopCommand::List, args );
                }
                else if ( cmd == "retr" && args->count() == 1 ) {
                    newCommand( d->commands, this, PopCommand::Retr, args );
                }
                else if ( cmd == "dele" && args->count() == 1 ) {
                    newCommand( d->commands, this, PopCommand::Dele, args );
                }
                else if ( cmd == "noop" && args->isEmpty() ) {
                    newCommand( d->commands, this, PopCommand::Noop );
                }
                else if ( cmd == "rset" && args->isEmpty() ) {
                    newCommand( d->commands, this, PopCommand::Rset );
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
        else {
            d->reader->read();
        }

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
    setReader( 0 );
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


/*! Sets the current user of this POP server to \a u. Called upon
    receipt of a valid USER command.
*/

void POP::setUser( User * u )
{
    d->user = u;
}


/*! Returns the current user of this POP server, or an empty string if
    setUser() has never been called upon receipt of a USER command.
*/

User * POP::user() const
{
    return d->user;
}


/*! Reserves the input stream to inhibit parsing if \a r is true. If
    \a r is false, then the server processes input as usual. Used by
    STLS to inhibit parsing.
*/

void POP::setReserved( bool r )
{
    d->reserved = r;
}


/*! Reserves the input stream for processing by \a cmd, which may be 0
    to indicate that the input should be processed as usual. Used by
    AUTH to parse non-command input.
*/

void POP::setReader( PopCommand * cmd )
{
    d->reader = cmd;
    d->reserved = d->reader;
}


/*! Returns true only if this POP server supports the authentication
    mechanism named \a s (which must be in lowercase).

    XXX: This is copied from IMAP. What to do about the duplication?
*/

bool POP::supports( const String &s ) const
{
    if ( ::supportsDigestMd5 && s == "digest-md5" )
        return true;

    if ( ::supportsCramMd5 && s == "cram-md5" )
        return true;

    if ( ::allowPlaintext || hasTls() ) {
        if ( ::supportsPlain && s == "plain" )
            return true;
        if ( ::supportsAnonymous && s == "anonymous" )
            return true;
        if ( s == "login" )
            return true;
    }

    return false;
}


/*! This setup function expects to be called from ::main().

    It reads and validates any relevant configuration variables, and
    logs a disaster if it encounters an error.
*/

void POP::setup()
{
    ::supportsPlain = Configuration::toggle( Configuration::AuthPlain );
    ::supportsCramMd5 =
          Configuration::toggle( Configuration::AuthCramMd5 );
    ::supportsDigestMd5 =
          Configuration::toggle( Configuration::AuthDigestMd5 );
    ::supportsAnonymous =
          Configuration::toggle( Configuration::AuthAnonymous );

    String s =
        Configuration::text( Configuration::AllowPlaintextPasswords ).lower();
    if ( s == "always" )
        ::allowPlaintext = true;
    else if ( s == "never" )
        ::allowPlaintext = false;
    else
        ::log( "Unknown value for allow-plaintext-passwords: " + s,
               Log::Disaster );
}


/*! Sets this POP server's Session object to \a s. */

void POP::setSession( Session * s )
{
    d->session = s;
}


/*! Returns this POP server's Session object, or 0 if none has been
    specified with setSession.
*/

Session * POP::session() const
{
    return d->session;
}
