#include "imap.h"

#include "command.h"
#include "mailbox.h"

#include <test.h>
#include <buffer.h>
#include <arena.h>
#include <list.h>
#include "handlers/capability.h"
#include "logger.h"

#include <time.h>


class IMAPData {
public:
    IMAPData():
        logger( 0 ), cmdArena( 0 ),
        readingLiteral( false ), literalSize( 0 ),
        args( 0 ),
        state( IMAP::NotAuthenticated ),
        grabber( 0 ),
        mailbox( 0 ),
        idle( false )
    {}

    Logger * logger;
    Arena * cmdArena;
    bool readingLiteral;
    uint literalSize;
    List<String> * args;
    IMAP::State state;
    Command * grabber;
    List<Command> commands;
    Mailbox *mailbox;
    String login;
    bool idle;
};


/*! \class IMAP

  \brief The IMAP class implements the IMAP server seen by clients.

  Most of IMAP functionality is in the command handlers, but this
  class contains the top-level responsibility and functionality. This
  class reads commands from its network connection, does basic
  parsing and creates command handlers as necessary.

  The IMAP state (RFC 3501 section 3) and Idle state (RFC 2177) are
  both encoded here, exactly as in the specification.
*/


/*! Creates a basic IMAP connection */

IMAP::IMAP(int s)
    : Connection(s), d(0)
{
    d = new IMAPData;

    d->logger = new Logger;
    d->logger->log( "accepted IMAP connection" ); // XXX: from where?

    writeBuffer()->append("* OK [CAPABILITY ");
    writeBuffer()->append( Capability::capabilities() );
    writeBuffer()->append( "]\r\n");
    setTimeout( time(0) + 20 );
}


/*! Destroys the object and closes its network connection. */

IMAP::~IMAP()
{
    delete d;
}


/*! Handles incoming data and timeouts. */

void IMAP::react(Event e)
{
    switch (e) {
    case Connection::Read:
        if ( !d->cmdArena )
            d->cmdArena = new Arena;
        if ( !d->args )
            d->args = new List<String>;
        Arena::push( d->cmdArena );
        parse();
        Arena::pop();
        break;
    case Connection::Timeout:
        writeBuffer()->append( "* BYE autologout\r\n" );
        d->logger->log( "autologout" );
        break;
    case Connection::Close:
        if ( state() != Logout )
            d->logger->log( "Unexpected close by client" );
        break;
    case Connection::Shutdown:
        writeBuffer()->append( "* BYE server shutdown\r\n" );
        break;
    }
    d->logger->commit();
    runCommands();
    d->logger->commit();
    setTimeout( time(0) + 20 );
    if ( state() == Logout )
        close();
}


void IMAP::parse()
{
    Buffer * r = readBuffer();
    while( true ) {
        if ( d->grabber ) {
            d->grabber->read();
            // still grabbed? must wait for more.
            if ( d->grabber )
                return;
        }
        else if ( d->readingLiteral ) {
            if ( r->size() >= d->literalSize ) {
                d->args->append( r->string( d->literalSize ) );
                r->remove( d->literalSize );
                d->readingLiteral = false;
            }
            else {
                return;
            }
        }
        else {
            uint i = 0;
            while( i < r->size() && (*r)[i] != 10 )
                i++;
            if ( (*r)[i] != 10 )
                return; // better luck next time

            // we have a line; read it and consider literals
            uint j = i;
            if ( i > 0 && (*r)[i-1] == 13 )
                j--;
            String * s = r->string( j );
            d->args->append( s );
            r->remove( i + 1 ); // string + trailing lf
            if ( s->endsWith( "}" ) ) {
                i = s->length()-2;
                bool plus = false;
                if ( (*s)[i] == '+' ) {
                    plus = true;
                    i--;
                }
                j = i;
                while( i > 0 && (*s)[i] >= '0' && (*s)[i] <= '9' )
                    i--;
                if ( (*s)[i] == '{' ) {
                    d->readingLiteral = true;
                    bool ok;
                    d->literalSize = s->mid( i+1, j-i+1 ).number( &ok );
                    if ( !ok ) {
                        writeBuffer()->append( "* BAD literal, BAD\r\n" );
                        close();
                        return;
                    }
                    if ( ok && !plus )
                        writeBuffer()->append( "+\r\n" );
                }
            }
            if ( !d->readingLiteral ) {
                addCommand();
                Arena::pop();
                d->cmdArena = new Arena;
                Arena::push( d->cmdArena );
            }
        }
    }
}


/*! Does preliminary parsing and adds a new Command object. At some
  point, that object may be executed - we don't care about that for
  the moment.

  During execution of this function, the command's Arena must be used.
*/

void IMAP::addCommand()
{
    List<String> * args = d->args;
    d->args = new List<String>;

    String * s = args->first();
    d->logger->log( Logger::Debug, "Received " +
                    String::fromNumber( (args->count() + 1)/2 ) +
                    "-line command: " + *s );

    // pick up the tag
    uint i = (uint)-1;
    uchar c;
    do {
        i++;
        c = (*s)[i];
    } while( i < s->length() &&
             c < 128 && c > ' ' && c != '+' &&
             c != '(' && c != ')' && c != '{' &&
             c != '%' && c != '%' );
    if ( i < 1 || c != ' ' ) {
        writeBuffer()->append( "* BAD tag\r\n" );
        d->logger->log( "Unable to parse tag. Line: " + *s );
        return;
    }
    String tag = s->mid( 0, i );

    // pick up the command
    uint j = i+1;
    do {
        i++;
        c = (*s)[i];
    } while( i < s->length() &&
             c < 128 &&
             ( c > ' ' ||
               ( c == ' ' && s->mid( j, i-j ).lower() == "uid" ) ) &&
             c != '(' && c != ')' && c != '{' &&
             c != '%' && c != '%' &&
             c != '"' && c != '\\' &&
             c != ']' );
    if ( i == j ) {
        writeBuffer()->append( "* BAD no command\r\n" );
        d->logger->log( "Unable to parse command. Line: " + *s );
        return;
    }
    String command = s->mid( j, i-j );

    // evil hack: skip past a space if there is one, for ease of
    // parsing by the Command classes.
    if ( (*s)[i] == ' ' )
        i++;

    // write the new string into the one in the list
    *s = s->mid( i );

    Command * cmd = Command::create( this, command, tag, args, d->cmdArena );
    if ( cmd ) {
        cmd->parse();
        if ( cmd->ok() && cmd->state() == Command::Executing &&
            !d->commands.isEmpty() ) {
            // we're already executing one or more commands. can this
            // one be started concurrently?
            if ( cmd->group() == 0 ) {
                // no, it can't.
                cmd->setState( Command::Blocked );
                cmd->logger()->log( Logger::Debug,
                                    "Blocking execution of " + tag +
                                    " (concurrency not allowed for " +
                                    command + ")" );
            }
            else {
                // do all other commands belong to the same command group?
                d->commands.first();
                while( d->commands.current() &&
                       d->commands.current()->group() == cmd->group() )
                    d->commands.next();
                if ( d->commands.current() ) {
                    // no, d->commands.current() does not
                    cmd->setState( Command::Blocked );
                    cmd->logger()->log( Logger::Debug,
                                        "Blocking execution of " + tag +
                                        " until it can be exectuted" );
                    // evil. we really want to say something about why
                    // it can't. but what?
                }
            }
        }
        d->commands.append( cmd );
    }
    else {
        d->logger->log( "Unknown command '" + command + "' (tag '" +
                        tag + "')" );
        String tmp( tag );
        tmp += " BAD command unknown: ";
        tmp += command;
        tmp += "\r\n";
        writeBuffer()->append( tmp );
    }
}


static class IMAPTest : public Test {
public:
    IMAPTest() : Test( 500 ) {}
    void test() {

    }
} imapTest;




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
    switch( s ) {
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
    d->logger->log( "Changed to " + name + " state" );
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
        d->logger->log( "entered idle mode" );
    else
        d->logger->log( "left idle mode" );
}


/*! Returns true if this connection is idle, and false if it is
  not. The initial (and normal) state is false.
*/

bool IMAP::idle() const
{
    return d->idle;
}


/*! Notifis the IMAP object that it's logged in as \a name. */

void IMAP::setLogin( const String & name )
{
    if ( state() != NotAuthenticated ) {
        // not sure whether I like this... on one hand, it does
        // prevent change of login. on the other, how could that
        // possibly happen?
        d->logger->log( Logger::Error,
                        "ignored setLogin("+name+") due to wrong state" );
        return;
    }
    d->login = name;
    d->logger->log( "logged in as " + name );
    setState( Authenticated );
}


/*! Returns the current login name. Initially, the login name is an
  empty string.

  The return value is meaningful only in Authenticated and Selected
  states.
*/

String IMAP::login()
{
    return d->login;
}


/*! Returns the currently-selected Mailbox. */
Mailbox *IMAP::mailbox()
{
    return d->mailbox;
}

/*! Sets the currently-selected Mailbox to \a m. */
void IMAP::setMailbox( Mailbox *m )
{
    if ( m == d->mailbox )
        return;
    d->mailbox = m;
    d->logger->log( "now using mailbox " + m->name() );
}

/*! Reserves input from the connection for \a command.

  When more input is available, \a Command::read() is called, and as
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
    d->grabber = command;
}


/*! Calls execute() on all currently operating commands, and if
  possible calls emitResponses() and retires those which can be
  retired.
*/

void IMAP::runCommands()
{
    Command * c;
    bool more = true;
    while( more ) {
        more = false;
        d->commands.first();
        while( (c=d->commands.current()) != 0 ) {
                Arena::push( c->arena() );
                if ( c->ok() && c->state() == Command::Executing )
                    c->execute();
                if ( !c->ok() )
                    c->setState( Command::Finished );
                if ( c->state() == Command::Finished )
                    c->emitResponses();
                Arena::pop();
                d->commands.next();
            }
            d->commands.first();
            while( (c=d->commands.current()) != 0 ) {
                if ( c->state() == Command::Finished ) {
                    d->commands.take();
                    delete c;
                }
                else {
                    d->commands.next();
                }
            }
        c = d->commands.first();
        if ( c && c->ok() && c->state() == Command::Blocked ) {
            c->setState( Command::Executing );
            more = true;
        }
    };

}
