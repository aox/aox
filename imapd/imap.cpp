// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imap.h"

#include "arena.h"
#include "scope.h"
#include "string.h"
#include "buffer.h"
#include "list.h"
#include "mailbox.h"
#include "command.h"
#include "handlers/capability.h"
#include "loop.h"
#include "log.h"
#include "configuration.h"
#include "imapsession.h"


static bool endsWithLiteral( const String *, uint *, bool * );


static bool allowPlaintext = true;
static bool supportsPlain = true;
static bool supportsCramMd5 = true;
static bool supportsDigestMd5 = true;
static bool supportsAnonymous = true;


class IMAPData {
public:
    IMAPData()
        : log( new Log( Log::IMAP ) ),
          state( IMAP::NotAuthenticated ),
          cmdArena( 0 ), args( 0 ), reader( 0 ),
          readingLiteral( false ), literalSize( 0 ),
          session( 0 ), mailbox( 0 ), uid( 0 ),
          idle( false )
    {}
    ~IMAPData() {
        delete cmdArena;
    }

    Log *log;

    IMAP::State state;

    Arena * cmdArena;
    StringList * args;
    Command * reader;

    bool readingLiteral;
    uint literalSize;

    List< Command > commands;

    ImapSession *session;
    Mailbox *mailbox;
    String login;
    uint uid;

    bool idle;
};


/*! \class IMAP imap.h
    This class implements the IMAP server as seen by clients.

    This class is responsible for interacting with IMAP clients, and for
    overseeing the operation of individual command handlers. It looks at
    client input to decide which Command to defer the real work to, and
    ensures that the handler is called at the appropriate times.

    Each IMAP object has a state() (RFC 3501, §3), and may possess other
    state information, such as the login() name or a session(). The Idle
    state (RFC 2177) is also kept here.

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
    Configuration::Text plaintext( "allow-plaintext", "always" );

    Configuration::Toggle plain( "auth-plain", true );
    Configuration::Toggle cramMd5( "auth-cram-md5", true );
    Configuration::Toggle digestMd5( "auth-digest-md5", true );
    Configuration::Toggle anonymous( "auth-anonymous", false );

    ::supportsPlain = plain;
    ::supportsCramMd5 = cramMd5;
    ::supportsDigestMd5 = digestMd5;
    ::supportsAnonymous = anonymous;

    String s = plaintext;
    if ( s.lower() == "always" )
        ::allowPlaintext = true;
    else if ( s.lower() == "never" )
        ::allowPlaintext = false;
    else
        log( Log::Disaster, "Unknown value for allow-plaintext." );
}


/*! Creates an IMAP server on file descriptor \a s, and sends an
    initial OK[CAPABILITY...] response to the client.
*/

IMAP::IMAP( int s )
    : Connection( s, Connection::ImapServer ), d( new IMAPData )
{
    if ( s < 0 )
        return;

    enqueue( "* OK [CAPABILITY " + Capability::capabilities( this ) + "] " +
             Configuration::hostname() + " IMAP Server\r\n" );
    setTimeoutAfter( 1800 );

    Loop::addConnection( this );
}


/*! Destroys the IMAP server. */

IMAP::~IMAP()
{
    Loop::removeConnection( this );
    delete d;
    d = 0;
}


/*! Handles the incoming event \a e as appropriate for its type. */

void IMAP::react( Event e )
{
    Scope x;
    x.setLog( d->log );

    switch ( e ) {
    case Read:
        setTimeoutAfter( 1800 );
        parse();
        break;

    case Timeout:
        enqueue( "* BYE autologout\r\n" );
        log( "autologout" );
        Connection::setState( Closing );
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

    d->log->commit();
    runCommands();
    d->log->commit();

    if ( timeout() == 0 )
        setTimeoutAfter( 1800 );
    if ( state() == Logout )
        Connection::setState( Closing );
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

        if ( !d->cmdArena )
            s.setArena( d->cmdArena = new Arena );
        if ( !d->args )
            d->args = new StringList;

        // We read a line of client input, possibly including literals,
        // and create a Command to deal with it.

        if ( !d->readingLiteral && !d->reader ) {
            uint n;
            bool plus;
            String * s;

            // Do we have a complete line yet?

            s = r->removeLine();
            if ( !s )
                return;

            d->args->append( s );

            if ( endsWithLiteral( s, &n, &plus ) ) {
                d->readingLiteral = true;
                d->literalSize = n;

                if ( !plus )
                    enqueue( "+\r\n" );
            }

            // Have we finished reading the entire command?

            if ( !d->readingLiteral ) {
                addCommand();
                d->cmdArena = 0;
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
    if ( s && s->simplified() == "quit" )
        s = new String( "quit logout\r\n" ); // arnt compatibility
    log( Log::Debug, "Received " +
                    fn( (d->args->count() + 1)/2 ) +
                    "-line command: " + *s );

    String tag, command;

    // Parse the tag: A nonzero sequence of any ASTRING-CHAR except '+'.

    char c;
    uint i = 0;

    while ( i < s->length() && ( c = (*s)[i] ) > ' ' && c < 127 &&
            c != '(' && c != ')' && c != '{' && c != '%' && c != '*' &&
            c != '"' && c != '\\' && c != '+' )
        i++;

    if ( i < 1 || c != ' ' ) {
        enqueue( "* BAD tag\r\n" );
        log( "Unable to parse tag. Line: " + *s );
        delete d->cmdArena;
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
        log( "Unable to parse command. Line: " + *s );
        delete d->cmdArena;
        return;
    }

    command = s->mid( j, i-j );

    // Try to create a command handler.

    Command *cmd
        = Command::create( this, command, tag, d->args, d->cmdArena );

    if ( !cmd ) {
        String st;
        switch( d->state ) {
        case NotAuthenticated:
            st = "unauthenticated";
            break;
        case Authenticated:
            st = "authenticated";
            break;
        case Selected:
            st = "selected";
            break;
        case Logout:
            st = "logout";
            break;
        }
        log( Log::Debug,
             "Unknown command '" + command +
             "' (tag '" + tag + "', state " + st + ")" );
        enqueue( tag + " BAD No such command in " + st + " state: " +
                 command + "\r\n" );
        delete d->cmdArena;
        return;
    }

    // Use this Command to parse the command line.

    cmd->step( i );
    cmd->parse();

    // If we're already working, block this. Otherwise, run
    // it. runCommands() will unblock it (at once or later).

    if ( !d->commands.isEmpty() && cmd->state() == Command::Executing ) {
        log( Log::Debug, "Blocking command '" + tag + " " + command +
             " because other commands are queued" );
        cmd->setState( Command::Blocked );
    }
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
    log( "Changed to " + name + " state" );
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
        log( "entered idle mode" );
    else
        log( "left idle mode" );
}


/*! Returns true if this connection is idle, and false if it is
    not. The initial (and normal) state is false.
*/

bool IMAP::idle() const
{
    return d->idle;
}


/*! Notifies the IMAP object that the user \a name with uid \a n, was
    successfully authenticated. This changes the state() of the IMAP
    object to Authenticated.
*/

void IMAP::authenticated( uint n, const String & name )
{
    d->uid = n;
    d->login = name;
    log( "Logged in as " + name );
    setState( Authenticated );
}


/*! Returns the current login name. Initially, the login name is an
    empty string.

    The return value is meaningful only in Authenticated and Selected
    states.
*/

String IMAP::login() const
{
    return d->login;
}


/*! Returns the user ID corresponding to the login() name set for this
    IMAP session, or 0 if none has been set.
*/

uint IMAP::uid() const
{
    return d->uid;
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


/*! Calls Command::execute() on all currently operating commands, and
    if possible calls Command::emitResponses() and retires those which
    can be retired.
*/

void IMAP::runCommands()
{
    Command * c;
    List< Command >::Iterator i;

    // run all currently executing commands once
    i = d->commands.first();
    while ( i ) {
        run( i );
        i++;
    }

    // if no commands are running, start the oldest blocked command
    // and all others in its group.

    i = d->commands.first();
    while ( i && i->state() != Command::Executing )
        i++;
    if ( !i ) {
        i = d->commands.first();
        while ( i && i->state() != Command::Blocked )
            i++;
    }
    if ( !i )
        return;

    c = i;
    do {
        if ( i->group() == c->group() &&
             i->state() == Command::Blocked && i->ok() ) {
            i->setState( Command::Executing );
            run( i );
        }
        i++;
    } while ( c->group() > 0 && i );

    // retire all finished commands

    i = d->commands.first();
    while ( i ) {
        if ( i->state() == Command::Finished )
            delete d->commands.take( i );
        else
            i++;
    }
}


/*! Executes \a c once, provided it's in the right state, and emits its
    responses.
*/

void IMAP::run( Command * c )
{
    if ( c->state() != Command::Executing )
        return;

    Scope x( c->arena() );

    if ( c->ok() && c->state() == Command::Executing )
        c->execute();
    if ( !c->ok() )
        c->setState( Command::Finished );
    if ( c->state() == Command::Finished )
        c->emitResponses();
    d->log->commit();
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
    *n = s->mid( i+1, j-i+1 ).number( &ok );

    return ok;
}


/*! This function returns the fully-qualified name of the mailbox \a m,
    using the current user's login() name to qualify it if necessary.
*/

String IMAP::mailboxName( const String &m ) const
{
    String name;

    if ( m[0] != '/' )
        name = "/users/" + login() + "/";
    if ( m.lower() == "inbox" )
        name.append( "INBOX" );
    else
        name.append( m );

    return name;
}


/*! Switches to Selected state and operates on the mailbox session \a s.

    This function may be called only when the server is in Authenticated
    state (and thus does not have a session() already defined).
*/

void IMAP::beginSession( ImapSession * s )
{
    d->session = s;
    setState( Selected );
    log( "Starting session on " + s->mailbox()->name() );
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
    delete d->session;
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
    List<Command>::Iterator i = d->commands.first();
    while ( i ) {
        if ( i->state() != Command::Finished )
            n++;
        i++;
    }
    return n;
}
