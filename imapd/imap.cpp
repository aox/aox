// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imap.h"

#include "scope.h"
#include "string.h"
#include "buffer.h"
#include "list.h"
#include "mailbox.h"
#include "command.h"
#include "handlers/capability.h"
#include "eventloop.h"
#include "log.h"
#include "configuration.h"
#include "imapsession.h"
#include "user.h"
#include "tls.h"


static bool endsWithLiteral( const String *, uint *, bool * );


static bool allowPlaintext = true;
static bool supportsPlain = true;
static bool supportsCramMd5 = true;
static bool supportsDigestMd5 = true;
static bool supportsAnonymous = true;


class IMAPData
    : public Garbage
{
public:
    IMAPData()
        : state( IMAP::NotAuthenticated ),
          args( 0 ), reader( 0 ),
          runningCommands( false ), readingLiteral( false ),
          literalSize( 0 ), session( 0 ), mailbox( 0 ), login( 0 ),
          idle( false )
    {}

    IMAP::State state;

    StringList * args;
    Command * reader;

    bool runningCommands;
    bool readingLiteral;
    uint literalSize;

    List< Command > commands;

    ImapSession *session;
    Mailbox *mailbox;
    User * login;

    bool idle;
};


/*! \class IMAP imap.h
    This class implements the IMAP server as seen by clients.

    This class is responsible for interacting with IMAP clients, and for
    overseeing the operation of individual command handlers. It looks at
    client input to decide which Command to defer the real work to, and
    ensures that the handler is called at the appropriate times.

    Each IMAP object has a state() (RFC 3501 section 3), and may possess
    other state information, such as the user() logged in or a
    session(). The Idle state (RFC 2177) is also kept here.

    The IMAP class parses incoming commands as soon as possible and
    may keep several commands executing at a time, if the client
    issues that. It depends on Command::group() to decide whether each
    parsed Command can be executed concurrently with the already
    running Command objects.
*/

/*! This setup function expects to be called from ::main().

    It reads and validates any relevant configuration variables, and
    logs a disaster if it encounters an error.
*/

void IMAP::setup()
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


/*! Creates an IMAP server on file descriptor \a s, and sends an
    initial OK[CAPABILITY...] response to the client.
*/

IMAP::IMAP( int s )
    : Connection( s, Connection::ImapServer ), d( new IMAPData )
{
    if ( s < 0 )
        return;

    enqueue( "* OK [CAPABILITY " +
             Capability::capabilities( this ) + "] " +
             Configuration::hostname() + " Archiveopteryx IMAP Server\r\n" );
    setTimeoutAfter( 120 );
    EventLoop::global()->addConnection( this );
}


/*! Handles the incoming event \a e as appropriate for its type. */

void IMAP::react( Event e )
{
    switch ( e ) {
    case Read:
        parse();
        break;

    case Timeout:
        if ( !d->commands.isEmpty() ) {
            enqueue( "* OK making progress" );
            break;
        }
        if ( state() != Logout ) {
            log( "Idle timeout" );
            enqueue( "* BYE autologout\r\n" );
        }
        Connection::setState( Closing );
        if ( d->reader )
            d->reader->read();
        break;

    case Connect:
    case Error:
    case Close:
        if ( state() != Logout )
            log( "Unexpected close by client" );
        Connection::setState( Closing );
        break;

    case Shutdown:
        enqueue( "* BYE server shutdown\r\n" );
        break;
    }

    runCommands();
    expireCommands();

    if ( e == Read || timeout() == 0 ) {
        switch ( state() ) {
        case NotAuthenticated:
            setTimeoutAfter( 120 );
            break;
        case Authenticated:
        case Selected:
            if ( d->commands.isEmpty() )
                setTimeoutAfter( 1800 );
            else
                setTimeoutAfter( 120 );
            break;
        case Logout:
            break;
        }

    }

    if ( state() == Logout || d->commands.isEmpty() )
        commit();
}


/*! Reads input from the client, and feeds it to the appropriate Command
    handlers.
*/

void IMAP::parse()
{
    Scope s;
    Buffer * r = readBuffer();

    while ( true ) {
        // We allocate and donate a new arena to each command we create,
        // and use it to allocate anything command-related in this loop.

        if ( !d->args )
            d->args = new StringList;

        // We read a line of client input, possibly including literals,
        // and create a Command to deal with it.

        if ( !d->readingLiteral && !d->reader ) {
            bool plus = false;
            String * s;
            uint n;

            // Do we have a complete line yet?

            s = r->removeLine();
            if ( !s )
                return;

            d->args->append( s );

            if ( endsWithLiteral( s, &n, &plus ) ) {
                d->readingLiteral = true;
                d->literalSize = n;

                if ( !plus )
                    enqueue( "+ reading literal\r\n" );
            }

            // Have we finished reading the entire command?

            if ( !d->readingLiteral ) {
                addCommand();
                d->args = 0;
            }
        }
        else if ( d->readingLiteral ) {
            // Have we finished reading a complete literal?
            if ( r->size() < d->literalSize )
                return;

            d->args->append( r->string( d->literalSize ) );
            r->remove( d->literalSize );
            d->readingLiteral = false;
        }
        else if ( d->reader ) {
            // If a Command has reserve()d input, we just feed it.
            d->reader->read();
            if ( d->reader )
                return;
        }
    }
}


/*! This function parses enough of the command line to create a Command,
    and then uses it to parse the rest of the input.
*/

void IMAP::addCommand()
{
    String * s = d->args->first();
    log( "Received " + fn( (d->args->count() + 1)/2 ) +
         "-line command: " + *s, Log::Debug );

    String tag, command;

    // Be kind to the old man Arnt, who cannot unlearn his SMTP habits

    if ( * s == "quit" )
        *s = "arnt logout";

    // Parse the tag: A nonzero sequence of any ASTRING-CHAR except '+'.

    char c = 0;
    uint i = 0;

    while ( i < s->length() && ( c = (*s)[i] ) > ' ' && c < 127 &&
            c != '(' && c != ')' && c != '{' && c != '%' && c != '*' &&
            c != '"' && c != '\\' && c != '+' )
        i++;

    if ( i < 1 || c != ' ' ) {
        enqueue( "* BAD tag in line: " + *s + "\r\n" );
        log( "Bad tag. Line: '" + *s + "'", Log::Info );
        return;
    }

    tag = s->mid( 0, i );

    // Parse the command name (a single atom possibly prefixed by "uid ").

    uint j = ++i;

    if ( s->mid( j, 4 ).lower() == "uid " )
        i = j + 4;

    while ( i < s->length() && ( c = (*s)[i] ) > ' ' && c < 127 &&
            c != '(' && c != ')' && c != '{' && c != '%' && c != '*' &&
            c != '"' && c != '\\' && c != ']' )
        i++;

    if ( i == j ) {
        enqueue( "* BAD no command\r\n" );
        log( "Bad command. Line: '" + *s + "'", Log::Error );
        return;
    }

    command = s->mid( j, i-j );

    // Try to create a command handler.

    Command * cmd = Command::create( this, command, tag, d->args );

    if ( !cmd ) {
        log( "Unknown command. Line: '" + *s + "'", Log::Error );
        enqueue( tag + " BAD No such command: " + command + "\r\n" );
        return;
    }

    cmd->step( i );
    d->commands.append( cmd );
}


/*! Returns the current state of this IMAP session, which is one of
    NotAuthenticated, Authenticated, Selected and Logout.
*/

IMAP::State IMAP::state() const
{
    return d->state;
}


/*! Sets this IMAP connection to be in state \a s. The initial value
    is NotAuthenticated.
*/

void IMAP::setState( State s )
{
    if ( s == d->state )
        return;
    d->state = s;
    String name;
    switch ( s ) {
    case NotAuthenticated:
        name = "not authenticated";
        break;
    case Authenticated:
        name = "authenticated";
        break;
    case Selected:
        name = "selected";
        break;
    case Logout:
        name = "logout";
        break;
    };
    log( "Changed to " + name + " state", Log::Debug );
}


/*! Notifies this IMAP connection that it is idle if \a i is true, and
    not idle if \a i is false. An idle connection (see RFC 2177) is one
    in which e.g. EXPUNGE/EXISTS responses may be sent at any time. If a
    connection is not idle, such responses must be delayed until the
    client can listen to them.
*/

void IMAP::setIdle( bool i )
{
    if ( i == d->idle )
        return;
    d->idle = i;
    if ( i )
        log( "entered idle mode", Log::Debug );
    else
        log( "left idle mode", Log::Debug );
}


/*! Returns true if this connection is idle, and false if it is
    not. The initial (and normal) state is false.
*/

bool IMAP::idle() const
{
    return d->idle;
}


/*! Notifies the IMAP object that \a user was successfully
    authenticated. This changes the state() of the IMAP object to
    Authenticated.
*/

void IMAP::authenticated( User * user )
{
    d->login = user;
    log( "Logged in as " + user->login() );
    setState( Authenticated );
}


/*! Returns the currently logged in user, or a null pointer if no user
    is logged in.
*/

User * IMAP::user() const
{
    return d->login;
}


/*! Reserves input from the connection for \a command.

    When more input is available, Command::read() is called, and as
    soon as the command has read enough, it must call reserve( 0 ) to
    hand the connection back to the general IMAP parser.

    Most commands should never need to call this; it is provided for
    commands that need to read more input after parsing has completed,
    such as IDLE and AUTHENTICATE.

    There is a nasty gotcha: If a command reserves the input stream and
    calls Command::error() while in Blocked state, the command is
    deleted, but there is no way to hand the input stream back to the
    IMAP object. Only the relevant Command knows when it can hand the
    input stream back.

    Therefore, Commands that call reserve() simply must hand it back properly
    before calling Command::error() or Command::setState().
*/

void IMAP::reserve( Command * command )
{
    d->reader = command;
}


/*! Causes any blocked commands to be executed if possible.
*/

void IMAP::unblockCommands()
{
    if ( !d->runningCommands )
        runCommands();
}


/*! Calls Command::execute() on all currently operating commands, and
    if possible calls Command::emitResponses() and retires those which
    can be retired.
*/

void IMAP::runCommands()
{
    d->runningCommands = true;
    bool done = false;

    while ( !done ) {
        done = true;

        // run all currently executing commands once
        List< Command >::Iterator i( d->commands );
        while ( i ) {
            run( i );
            ++i;
        }

        // if no commands are running, start the oldest blocked command
        // and any following commands in the same group.

        i = d->commands.first();
        while ( i && i->state() != Command::Executing )
            ++i;
        if ( !i ) {
            i = d->commands.first();
            while ( i && i->state() != Command::Blocked )
                ++i;
        }
        if ( i ) {
            if ( i->state() == Command::Blocked ) {
                i->setState( Command::Executing );
                done = false;
            }
            if ( i->group() ) {
                Command * c = i;
                ++i;
                while ( i &&
                        i->group() == c->group() &&
                        i->state() == Command::Blocked &&
                        i->ok() ) {
                    i->setState( Command::Executing );
                    done = false;
                    i++;
                }
            }
        }

        // if there are any unparsed commands, start at the oldest
        // unparsed commands and parse contiguous commands until a
        // command isn't valid in this state.

        i = d->commands.first();
        while ( i && i->state() != Command::Unparsed )
            ++i;
        if ( i ) {
            // check whether there is at least one executing command
            while ( i && i->state() == Command::Unparsed ) {
                List< Command >::Iterator r( d->commands );
                while ( r && r->state() != Command::Executing )
                    ++r;
                Command * c = i;
                ++i;
                if ( c->validIn( d->state ) ) {
                    done = false;
                    c->parse();
                    // we've parsed it. did it return an error, should
                    // we block it, or perhaps execute it right away?
                    if ( c->state() == Command::Unparsed && c->ok() ) {
                        if ( r )
                            c->setState( Command::Blocked );
                        else
                            c->setState( Command::Executing );
                    }
                }
                else if ( !r ) {
                    done = false;
                    // if this command isn't valid in this state, and
                    // no earlier command can possibly change the
                    // state, then we have to reject the command.
                    c->error( Command::Bad, "Not permitted in this state" );
                }
            }
        }
    }

    d->runningCommands = false;
}


/*! Removes all commands that have finished executing from d->commands.
*/

void IMAP::expireCommands()
{
    List< Command >::Iterator i( d->commands );
    while ( i ) {
        if ( i->state() == Command::Finished )
            d->commands.take( i );
        else
            ++i;
    }
}


/*! Executes \a c once, provided it's in the right state, and emits its
    responses.
*/

void IMAP::run( Command * c )
{
    if ( c->state() != Command::Executing )
        return;

    if ( c->ok() )
        c->execute();
    else
        c->finish();
}


/*  This static helper function returns true if \a s ends with an IMAP
    literal specification. If so, it sets \a *n to the number of bytes
    in the literal, and \a *plus to true if the number had a trailing
    '+' (for LITERAL+). Returns false if it couldn't find a literal.
*/

static bool endsWithLiteral( const String *s, uint *n, bool *plus )
{
    if ( !s->endsWith( "}" ) )
        return false;

    uint i = s->length() - 2;
    if ( (*s)[i] == '+' ) {
        *plus = true;
        i--;
    }

    uint j = i;
    while ( i > 0 && (*s)[i] >= '0' && (*s)[i] <= '9' )
        i--;

    if ( (*s)[i] != '{' )
        return false;

    bool ok;
    *n = s->mid( i+1, j-i ).number( &ok );

    return ok;
}


/*! This function returns the fully-qualified name of the mailbox \a m,
    using the current user() to qualify it if necessary.
*/

String IMAP::mailboxName( const String &m ) const
{
    String name;

    if ( m[0] == '/' || !d->login )
        return m;

    if ( m.lower() == "inbox" )
        return user()->inbox()->name();
    return user()->home()->name() + "/" + m;
}


/*! Switches to Selected state and operates on the mailbox session \a s.

    This function may be called only when the server is in Authenticated
    state (and thus does not have a session() already defined).
*/

void IMAP::beginSession( ImapSession * s )
{
    d->session = s;
    setState( Selected );
    log( "Starting session on mailbox " + s->mailbox()->name() );
}


/*! Returns a pointer to the ImapSession object associated with this
    IMAP server, or 0 if there is none (which can happen only if the
    server is not in the Selected state).
*/

ImapSession *IMAP::session() const
{
    return d->session;
}


/*! This function deletes any existing ImapSession associated with this
    server, whose state changes to Authenticated. It must not be called
    unless the server has a session().
*/

void IMAP::endSession()
{
    setState( Authenticated );
    d->session = 0;
}


/*! Returns true only if this IMAP server supports the authentication
    mechanism named \a s (which must be in lowercase).
*/

bool IMAP::supports( const String &s ) const
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


/*! Returns the total number of unfinished commands. */

uint IMAP::activeCommands() const
{
    uint n = 0;
    List<Command>::Iterator i( d->commands );
    while ( i ) {
        if ( i->state() != Command::Finished )
            n++;
        ++i;
    }
    return n;
}


class IMAPSData
    : public Garbage
{
public:
    IMAPSData() : tlsServer( 0 ), helper( 0 ) {}
    TlsServer * tlsServer;
    String banner;
    class ImapsHelper * helper;
};

class ImapsHelper: public EventHandler
{
public:
    ImapsHelper( IMAPS * connection ) : c( connection ) {}
    void execute() { c->finish(); }

private:
    IMAPS * c;
};

/*! \class IMAPS imap.h

    The IMAPS class implements the old wrapper trick still commonly
    used on port 993. As befits a hack, it is a bit of a hack, and
    depends on the ability to empty its writeBuffer().
*/

/*! Constructs an IMAPS server on file descriptor \a s, and starts to
    negotiate TLS immediately.
*/

IMAPS::IMAPS( int s )
    : IMAP( s ), d( new IMAPSData )
{
    String * tmp = writeBuffer()->removeLine();
    if ( tmp )
        d->banner = *tmp;
    d->helper = new ImapsHelper( this );
    d->tlsServer = new TlsServer( d->helper, peer(), "IMAPS" );
    EventLoop::global()->removeConnection( this );
}


/*! Handles completion of TLS negotiation and sends the banner. */

void IMAPS::finish()
{
    if ( !d->tlsServer->done() )
        return;
    if ( !d->tlsServer->ok() ) {
        log( "Cannot negotiate TLS", Log::Error );
        close();
        return;
    }

    startTls( d->tlsServer );
    enqueue( d->banner + "\r\n" );
}
