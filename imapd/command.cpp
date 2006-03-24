// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "command.h"

#include "buffer.h"
#include "mailbox.h"
#include "imapsession.h"
#include "imap.h"
#include "messageset.h"
#include "log.h"

// Keep these alphabetical.
#include "handlers/acl.h"
#include "handlers/append.h"
#include "handlers/authenticate.h"
#include "handlers/capability.h"
#include "handlers/close.h"
#include "handlers/copy.h"
#include "handlers/create.h"
#include "handlers/delete.h"
#include "handlers/expunge.h"
#include "handlers/fetch.h"
#include "handlers/id.h"
#include "handlers/idle.h"
#include "handlers/listext.h"
#include "handlers/login.h"
#include "handlers/logout.h"
#include "handlers/lsub.h"
#include "handlers/namespace.h"
#include "handlers/noop.h"
#include "handlers/obliterate.h"
#include "handlers/rename.h"
#include "handlers/search.h"
#include "handlers/select.h"
#include "handlers/starttls.h"
#include "handlers/status.h"
#include "handlers/store.h"
#include "handlers/subscribe.h"
#include "handlers/unselect.h"
#include "handlers/view.h"

#include <sys/time.h> // gettimeofday, struct timeval


class CommandData
    : public Garbage
{
public:
    CommandData():
        at( 0 ), args( 0 ),
        responded( false ), tagged( false ),
        canExpunge( false ), error( false ),
        state( Command::Unparsed ), group( 0 ),
        permittedStates( 0 ),
        imap( 0 )
    {
        (void)::gettimeofday( &started, 0 );
    }

    String tag;

    uint at;
    List< String > * args;

    List< String > responses;
    bool responded;
    bool tagged;
    bool canExpunge;

    bool error;
    Command::State state;
    uint group;
    Command::Error errorCode;
    String errorText;

    uint permittedStates;

    struct timeval started;

    IMAP * imap;
};


/*! \class Command command.h
    The Command class represents a single IMAP command.

    Subclasses implement each command (e.g. Noop implements Noop), this
    class provides the overall framework.

    It contains convenience functions to parse the various arguments,
    such as atom(), astring(), set and so on, as well as utility
    functions for the Command subclasses and, naturally, some functions
    that are tightly bound with the Commands, viz:

    setGroup() and group() provide the IMAP class with information about
    which Commands can be executed concurrently.

    setState() and state() decribe a command's state, which is either
    Blocked (waiting until IMAP permits executing this command),
    Executing or Finished.

    respond(), emitResponses(), error() and ok() all help sending
    responses to the IMAP client. respond() is mostly used for
    untagged responses, error() for tagged NO/BAD responses. If
    neither respond() nor error() is called, a tagged OK is sent by
    default when emitResponses() is called at the end of
    processing. Finally, ok() returns false if anything has happened
    to warrant NO/BAD, and true if everything is still OK.
*/


/*! Constructs a simple Command, entirely empty. */

Command::Command()
    : d( new CommandData )
{
}


/*! Destroys the object and frees any allocated resources. */

Command::~Command()
{
}


/*! This static function creates an instance of the right subclass of
    Command, depending on \a name and the state of \a imap. \a args is a
    list of strings comprising the arguments to the command and \a tag
    is its tag. Command assumes ownership of \a args. \a args must not
    be null.

    If \a name is not a valid command, create() return a null pointer.
*/

Command * Command::create( IMAP * imap,
                           const String & name,
                           const String & tag,
                           StringList * args )
{
    Command * c = 0;
    String n = name.lower();
    bool uid = false;
    if ( n.startsWith( "uid " ) ) {
        uid = true;
        n = n.mid( 4 );
    }

    bool notAuthenticated = false;
    bool authenticated = false;
    bool selected = false;
    bool logout = false;

    // Create an appropriate Command handler.
    if ( n == "login" )
        c = new Login;
    else if ( n == "authenticate" )
        c = new Authenticate;
    else if ( n == "starttls" )
        c = new StartTLS;

    if ( c )
        notAuthenticated = true;

    if ( !c ) {
        if ( n == "select" )
            c = new Select;
        else if ( n == "examine" )
            c = new Examine;
        else if ( n == "create" )
            c = new Create;
        else if ( n == "delete" )
            c = new Delete;
        else if ( n == "list" )
            c = new Listext;
        else if ( n == "lsub" )
            c = new Lsub;
        else if ( n == "namespace" )
            c = new Namespace;
        else if ( n == "status" )
            c = new Status;
        else if ( n == "rename" )
            c = new Rename;
        else if ( n == "subscribe" )
            c = new Subscribe;
        else if ( n == "unsubscribe" )
            c = new Unsubscribe;
        else if ( n == "append" )
            c = new Append;
        else if ( n == "setacl" )
            c = new Acl( Acl::SetAcl );
        else if ( n == "deleteacl" )
            c = new Acl( Acl::DeleteAcl );
        else if ( n == "getacl" )
            c = new Acl( Acl::GetAcl );
        else if ( n == "listrights" )
            c = new Acl( Acl::ListRights );
        else if ( n == "myrights" )
            c = new Acl( Acl::MyRights );
        else if ( n == "view" )
            c = new View;
        else if ( n == "x-obliterate" )
            c = new XObliterate;

        if ( c ) {
            authenticated = true;
            selected = true;
        }
    }

    if ( !c ) {
        if ( n == "fetch" )
            c = new Fetch( uid );
        else if ( n == "search" )
            c = new Search( uid );
        else if ( n == "expunge" )
            c = new Expunge( uid );
        else if ( n == "check" )
            c = new Check;
        else if ( n == "close" )
            c = new Close;
        else if ( n == "store" )
            c = new Store( uid );
        else if ( n == "copy" )
            c = new Copy( uid );
        else if ( n == "unselect" )
            c = new Unselect;

        if ( c )
            selected = true;
    }

    if ( !c ) {
        if ( n == "noop" )
            c = new Noop;
        else if ( n == "capability" )
            c = new Capability;
        else if ( n == "logout" )
            c = new Logout;
        else if ( n == "idle" )
            c = new Idle;
        else if ( n == "id" )
            c = new Id;

        if ( c ) {
            notAuthenticated = true;
            authenticated = true;
            selected = true;
            logout = true;
        }
    }

    if ( !c )
        return 0;

    c->d->tag = tag;
    c->d->args = args;
    c->d->imap = imap;

    if ( notAuthenticated )
        c->d->permittedStates |= ( 1 << IMAP::NotAuthenticated );
    if ( authenticated )
        c->d->permittedStates |= ( 1 << IMAP::Authenticated );
    if ( selected )
        c->d->permittedStates |= ( 1 << IMAP::Selected );
    if ( logout )
        c->d->permittedStates |= ( 1 << IMAP::Logout );

    // we can send expunges provided we're in selected state, and the
    // command neither uses MSNs nor is called "search". the bit about
    // search makes little sense, but it's specified in the RFC, so...
    if ( selected && n != "search" )
        c->d->canExpunge = true;

    c->setLog( new Log( Log::IMAP ) );
    c->log( "IMAP Command: " + n + " Tag: " + tag, Log::Debug );

    return c;
}


/*! This virtual function is responsible for parsing the entire
    command. It may not return any value; instead, it may set an error
    by calling error(). It may also not do any database lookups or
    other "slow" work.

    If this function (or a reimplementation) is called and does not
    call error() or set the command's state, IMAP changes the state to
    Executing afterwards.

    The default implementation is suitable for argumentless commands
    such as logout, capability and starttls.
*/

void Command::parse()
{
    end();
}


/*! \fn void Command::execute()

    This virtual function is responsible for executing the command, as
    appopriate, and setting state() to Finished when it is. It is
    called by IMAP after parse() finishes, and only if parse()
    succeeds.

    If state() is still Executing after a call to execute(), IMAP will
    call it again later.
*/


/*! This virtual function is responsible for reading from the IMAP
    stream and eventually releasing a reservation. Most subclasses
    will not need to implement this; only those that call
    IMAP::reserve() to the IMAP input stream do.
*/

void Command::read()
{
    imap()->reserve( 0 );
}


/*! Returns true if there haven't been any errors so far during
    parsing or execution of this command.

    Calling error() makes this function return false.
*/

bool Command::ok() const
{
    if ( d->error )
        return false;
    return true;
}


/*! Returns the state of this command, which may be Blocked, Executing
    or Finished. See setState().
*/

Command::State Command::state() const
{
    return d->state;
}


/*! Sets the state of this command to \a s. The state is always one of
    three values, Blocked, Executing and Finished. The initial value is
    Executing. execute() must set it to Finished when done.

    The Blocked state means that execute() cannot be called until all
    currently executing commands have finished. parse() and read() both
    may be called.

    The Executing state means that execute() should be called (again).

    The Finished state means that the command is done. IMAP rechecks the
    state after calling execute.
*/

void Command::setState( State s )
{
    if ( d->state == s )
        return;

    d->state = s;
    switch( s ) {
    case Unparsed:
        // this is the initial state, it should never be called.
        break;
    case Blocked:
        log( "IMAP command execution deferred", Log::Debug );
        break;
    case Executing:
        (void)::gettimeofday( &d->started, 0 );
        log( "Executing IMAP command", Log::Debug );
        break;
    case Finished:
        struct timeval end;
        (void)::gettimeofday( &end, 0 );
        long elapsed = ( end.tv_sec * 1000000 + end.tv_usec ) -
                       ( d->started.tv_sec * 1000000 + d->started.tv_usec );
        Log::Severity level = Log::Debug;
        if ( elapsed > 1500 ) // XXX needs tweaking
            level = Log::Error;
        String m;
        m.append( "Executed IMAP command in " );
        m.append( fn( ( elapsed + 499 ) / 1000 ) );
        m.append( "ms" );
        log( m, level );
        break;
    }
}


/*! Returns true only if this command is valid when the IMAP server is
    in state \a s. Commands are assumed to be parseable in any state,
    but executable only when this function says so.
*/

bool Command::validIn( IMAP::State s ) const
{
    return d->permittedStates & ( 1 << s );
}


/*! Returns the command group of this Command. Commands in group 0 may
    only be executed singly, commands in other groups may be executed
    concurrently with other commands in the same group.

    The initial value is 0. setGroup() defines the available groups.
*/

uint Command::group() const
{
    return d->group;
}


/*! Sets this command to belong to group \a g. If \a g is 0, the
    command must be executed singly. If \a g is nonzero, IMAP may try to
    execute this command concurrently with any other commands whose
    group is \a g.

    The groups are (subject to later change):

    0) Most commands.

    1) UID SEARCH and UID FETCH. (If UID SEARCH sees that there are MSNs
    in the search arguments, it has to move itself to class 0.)

    2) FETCH and SEARCH.

    3) STORE and UID STORE. (Note that for this group to work, the server
    cannot emit side-effect expunges during UID STORE processing.)

    4) EXAMINE, STATUS, LIST. Perhaps other read-only commands that look
    at mailboxes.

    The initial value is 0.
*/

void Command::setGroup( uint g )
{
    d->group = g;
}


/*! Returns a pointer to the IMAP session to which this command
    belongs.
*/

IMAP * Command::imap() const
{
    return d->imap;
}


/*! Adds \a r to the list of strings to be sent to the client, and
    perhaps sends it right away, depending on whether it's acceptable
    to send output at the moment. By default \a r is sent as an
    untagged response, but if \a t is specified and has value Tagged,
    \a r is sent as a tagged response.

    \a r should not be CRLF-terminated.

    If emitResponses() has been called already, this function does
    nothing.
*/

void Command::respond( const String & r, Response t )
{
    String * tmp = new String;
    if ( t == Tagged ) {
        *tmp = d->tag;
        d->tagged = true;
    }
    else {
        *tmp = "*";
    }
    tmp->append( " " );
    tmp->append( r );
    tmp->append( "\r\n" );
    d->responses.append( tmp );
}


/*! Sets the command's status code to be \a e and the attendant
    debugging message to be \a t, provided no status code has been set
    yet.

    Only the first call to error() has any effect, and only if it's
    before the call to emitResponses(); subsequent calls are ignored
    entirely.

    \a t should not be CRLF-terminated.
*/

void Command::error( Error e, const String & t )
{
    if ( d->error )
        return;
    d->errorCode = e;
    d->errorText = t;
    d->error = true;
    finish();
}


/*! Sets this Command's state to ::Finished and immediately emits any
    queued responses.
*/

void Command::finish()
{
    setState( Finished );
    emitResponses();
    commit();
    imap()->unblockCommands();
}


/*! Dumps all responses issued during the command's parsing and
    execution to the write buffer. This may turn out to be insufficient,
    but for the moment it guarantees that each command's untagged
    responses and final tagged response come together.

    If this function is called multiple times, only the first call does
    anything.
*/

void Command::emitResponses()
{
    if ( d->responded )
        return;
    d->responded = true;

    if ( !d->tagged ) {
        if ( !d->error )
            respond( "OK done", Tagged );
        else if ( d->errorCode == Bad )
            respond( "BAD " + d->errorText, Tagged );
        else
            respond( "NO " + d->errorText, Tagged );
    }

    List< String >::Iterator it( d->responses );
    while ( it ) {
        if ( !it->startsWith( "* " ) &&
             d->canExpunge &&
             imap()->state() == IMAP::Selected &&
             imap()->activeCommands() == 0 &&
             imap()->session()->responsesNeeded() )
            imap()->session()->emitResponses();
        imap()->enqueue( *it );
        ++it;
    }

    imap()->write();
}


/*! Returns the next, unparsed character, without consuming
    it. Returns 0 in case of error, but does not emit any error
    messages.
*/

char Command::nextChar()
{
    String * l = d->args->first();
    if ( !l )
        return 0; // should we error()? no.

    return (*l)[d->at];
}


/*! Steps past \a n characters of the unparsed arguments. */

void Command::step( uint n )
{
    d->at = d->at + n;
}


/*! Checks whether the next characters in the input match \a s. If so,
    present() steps past the matching characters and returns true. If
    not, it returns false without changing the input.

    Note that the match is completely case insensitive.
*/

bool Command::present( const String & s )
{
    if ( s.isEmpty() )
        return true;

    String l = d->args->first()->mid( d->at, s.length() ).lower();
    if ( l != s.lower() )
        return false;

    step( s.length() );
    return true;
}


/*! Verifies that the next characters in the input match \a s (case
    insensitively), and removes whatever matches. If input isn't as
    required, require() calls error().
*/

void Command::require( const String & s )
{
    if ( !present( s ) )
        error( Bad, "Expected: '" + s + "', got: " + following() );
}


/*! Parses from \a min to \a max digits and returns them in string
    form. If less than \a min digits are available, error() is called.
*/

String Command::digits( uint min, uint max )
{
    String r;
    uint i = 0;
    char c = nextChar();
    while ( i < max && c >= '0' && c <= '9' ) {
        step();
        r.append( c );
        c = nextChar();
        i++;
    }
    if ( i < min )
        error( Bad, "Expected at least " + fn( min-i ) +
               " more digits, saw " + following() );
    return r;
}


/*! Parses from \a min to \a max letters and returns them in string
    form. If less than \a min letters are available, error() is
    called.
*/

String Command::letters( uint min, uint max )
{
    String r;
    uint i = 0;
    char c = nextChar();
    while ( i < max &&
            ( ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' ) ) ) {
        step();
        r.append( c );
        c = nextChar();
        i++;
    }
    if ( i < min )
        error( Bad, "Expected at least " + fn( min-i ) +
               " more letters, saw " + following() );
    return r;
}


/*! Checks that the atom "nil" is next at the parse position, and
    steps past. */

void Command::nil()
{
    String n = atom();
    if ( n.lower() != "nil" )
        error( Bad, "expected NIL, saw " + n );
}


/*! Checks that a single space is next at the parse position, and
    steps past it if all is ok.

    This command accepts more than one space, and gives a
    warning. This is to tolerate broken clients, while giving client
    authors a strong hint.
*/

void Command::space()
{
    require( " " );
    if ( nextChar() != ' ' )
        return;

    while ( nextChar() == ' ' )
        step();
    respond( "BAD Illegal space seen before this text: " + following(),
             Untagged );
}


/*! Parses a single number and returns it. */

uint Command::number()
{
    String s;
    char c = nextChar();

    bool zero = false;
    if ( c == '0' )
        zero = true;

    while ( c >= '0' && c <= '9' ) {
        s.append( c );
        step();
        c = nextChar();
    }

    bool ok = true;
    uint u = s.number( &ok );
    if ( !ok )
        error( Bad, "number expected, saw: " + s + following() );
    else if ( u > 0 && zero )
        error( Bad, "Zero used as leading digit" );

    return u;
}


/*! Parses a single nzNumber and returns it. */

uint Command::nzNumber()
{
    uint u = number();
    if ( u == 0 )
        error( Bad, "nonzero number expected, saw 0, then " + following() );
    return u;
}


/*! Parses an IMAP atom and returns it as a string. Calls error() and
    turns an empty string in case of error.
*/

String Command::atom()
{
    String result;
    char c = nextChar();
    while ( c > ' ' && c < 127 &&
            c != '(' && c != ')' && c != '{' &&
            c != ']' &&
            c != '"' && c != '\\' &&
            c != '%' && c != '*' )
    {
        result.append( c );
        step();
        c = nextChar();
    }
    if ( result.isEmpty() )
        error( Bad, "atom expected, saw: " + following() );
    return result;
}


/*! Parses one or more consecutive list-chars (ATOM-CHAR/list-wildcards/
    resp-specials) and returns them as a String. Calls error() and
    returns an empty string in case of error.
*/

String Command::listChars()
{
    String result;

    char c;
    while ( ( c = nextChar() ) > ' ' && c < 127 &&
            c != '(' && c != ')' && c != '{' &&
            c != '"' && c != '\\' )
    {
        result.append( c );
        step();
    }

    if ( result.isEmpty() )
        error( Bad, "Expected 1*list-char, saw: " + following() );
    return result;
}


/*! Parses an IMAP quoted string and return the relevant string. In
    case of error an empty string is returned.

    Note that any character can be quoted. IMAP properly allows only
    the quote character and the backslash to be quoted. In this
    respect, we deviate from the standard.
*/

String Command::quoted()
{
    char c = nextChar();
    String result;
    if ( c != '"' ) {
        error( Bad, "quoted string expected, saw: " + following() );
        return result;
    }
    step();
    c = nextChar();
    while ( c != '"' && c < 128 && c > 0 && c != 10 && c != 13 ) {
        if ( c == '\\' ) {
            step();
            c = nextChar();
            if ( c == 0 || c >= 128 || c == 10 || c == 13 )
                error( Bad,
                       "quoted string contained bad char: " + following() );
        }
        result.append( c );
        step();
        c = nextChar();
    }
    if ( c != '"' )
        error( Bad, "quoted string incorrectly terminated: " + following() );
    else
        step();
    return result;
}


/*! Parses an IMAP literal and returns the relevant string. Returns an
    empty string in case of error.
*/

String Command::literal()
{
    char c = nextChar();
    if ( c != '{' ) {
        error( Bad, "literal expected, saw: " + following() );
        return String();
    }
    step();
    (void)number(); // read and ignore
    if ( nextChar() == '+' )
        step();
    if ( nextChar() != '}' ) {
        error( Bad, "literal ('}') expected, saw: " + following() );
        return String();
    }
    if ( d->at < d->args->first()->length() - 1 ) {
        error( Bad, "CRLF expected as part of literal" );
        return String();
    }
    // ok, we've seen the CRLF, so next is the literal. ta-da! as it
    // happens, we know the size of the literal is right, because the
    // IMAP server made it be so.
    d->at = 0;
    d->args->shift();
    String * result = d->args->shift();
    if ( result )
        return *result;
    // just to avoid a segfault in case of bugs
    error( No, "Internal error" );
    return String();
}


/*! Parses an IMAP string and returns it. If there is none, error() is
    called appropriately.
*/

String Command::string()
{
    char c = nextChar();
    if ( c == '"' )
        return quoted();
    else if ( c == '{' )
        return literal();

    error( Bad, "string expected, saw: " + following() );
    return 0;
}


/*! Parses an IMAP nstring and returns that string. If the nstring is
    NIL, an empty string is returned and error() is called.
*/

String Command::nstring()
{
    char c = nextChar();
    if ( c == '"' || c == '{' )
        return string();

    nil();
    return 0;
}


/*! Parses an IMAP astring and returns that string. In case of error,
    astring() calls error() appropriately and returns an empty string.
*/

String Command::astring()
{
    char c = nextChar();
    if ( c == '"' || c == '{' )
        return string();
    String result;
    while ( c > ' ' && c < 128 &&
            c != '(' && c != ')' && c != '{' &&
            c != '"' && c != '\\' &&
            c != '%' && c != '*' ) {
        result.append( c );
        step();
        c = nextChar();
    }
    if ( result.isEmpty() )
        error( Bad, "astring expected, saw: " + following() );
    return result;
}


/*! Parses an IMAP set and returns the corresponding MessageSet object.
    The set always contains UIDs; this function creates an UID set even
    if \a parseMsns is true.
*/

MessageSet Command::set( bool parseMsns = false )
{
    MessageSet result;
    ImapSession *s = 0;
    if ( imap() )
        s = imap()->session();

    uint n1 = 0, n2 = 0;
    bool done = false;
    while ( ok() && !done ) {
        char c = nextChar();
        if ( c == '*' ) {
            step();
            n1 = UINT_MAX;
            if ( s )
                n1 = s->uid( s->count() );
        }
        else if ( c >= '1' && c <= '9' ) {
            if ( parseMsns )
                n1 = msn();
            else
                n1 = nzNumber();
        }
        else {
            error( Bad, "number or '*' expected, saw: " + following() );
        }
        c = nextChar();
        if ( c == ':' ) {
            if ( n2 )
                error( Bad,
                       "saw colon after range (" + fn( n1 ) + ":" +
                       fn( n2 ) + "), saw:" + following() );
            n2 = n1;
            n1 = 0;
            step();
        }
        else {
            if ( n2 )
                result.add( n1, n2 );
            else
                result.add( n1 );
            n1 = 0;
            n2 = 0;
            if ( c == ',' )
                step();
            else
                done = true;
        }
    };

    uint expunged = 0;
    if ( s ) {
        // if the parsed set contains some expunged messages, remove
        // them and give the client a tagged OK with a note.
        MessageSet e( s->expunged().intersection( result ) );
        uint i = 1;
        while ( i <= e.count() ) {
            uint u = e.value( i );
            result.remove( u );
            respond( "OK Ignoring expunged message with UID " + fn( u ) );
            expunged = u;
            i++;
        }
        // in addition to expunged messages, we may want to remove any
        // UIDs that just happen to be invalid? probably yes.
        result = result.intersection( s->messages() );
    }

    // if the client fetches only expunged messages and we cannot send
    // it EXPUNGE responses, reject the command with NO, as in RFC
    // 2180 section 4.1.1
    if ( parseMsns && expunged && result.isEmpty() )
        error( No, "Message " + fn( s->msn( expunged ) ) + " is expunged" );
    return result;
}


/*! Parses a single MSN and returns the accompanying UID. */

uint Command::msn()
{
    Mailbox *m;
    ImapSession *session = imap()->session();
    if ( !session || ( m = session->mailbox() ) == 0 ) {
        error( Bad, "Need mailbox to parse MSN" );
        return 1;
    }

    d->canExpunge = false;

    uint star = session->count();
    uint r = star;
    if ( nextChar() == '*' ) {
        step();
        if ( star == 0 )
            error( Bad, "* is not valid as MSN in an empty mailbox" );
    }
    else {
        r = nzNumber();
    }

    if ( r > star ) // should we send an EXISTS here?
        error( Bad,
               "MSN " + fn( r ) + " is too large. Highest MSN is " +
               fn( star ) + "." );

    return session->uid( r );
}


/*! Parses a flag name and returns it as a string, or calls error() if
    no valid flag name was present. The return value may contain both
    upper and lower case letters.
*/

String Command::flag()
{
    if ( !present( "\\" ) )
        return atom();

    String r = "\\" + atom();
    String l = r.lower();
    if ( l == "\\answered" || l == "\\flagged" || l == "\\deleted" ||
         l == "\\seen" || l == "\\draft" )
        return r;

    error( Bad, r + " is not a legal flag" );
    return "";
}


/*! Asserts that the end of parsing has been reached. If the IMAP
    client has supplied more text, that text is a parse error and
    results in a BAD response.
*/

void Command::end()
{
    // if we have more literals to parse, we can't be done.
    if ( d->args->count() > 1 ) {
        error( Bad, "Unparsed literals" );
        return;
    }

    // if this is indeed the last line, we need to be a little more
    // careful.
    String * l = d->args->first();
    if ( !l ) // empty list: ok
        return;
    if ( l->isEmpty() ) // reached end of string: ok
        return;

    // are we at the end of that line?
    if ( l->mid( d->at ).isEmpty() )
        return;

    // there is more text here, no question about it. so let's make up
    // a decent error message to help us debug the parser.
    error( Bad, String( "More text follows end of command: " ) + following() );
}


/*! This private utility function returns a const string of no more
    than 15 characters containing the first unparsed bits of input.
*/

const String Command::following() const
{
    String * l = d->args->first();
    if ( !l )
        return String();

    return l->mid( d->at, 15 ).simplified();
}


/*! This helper returns \a s, quoted such that an IMAP client will
    recover \a s. The quoted string fits the IMAP productions astring,
    nstring or string, depending on \a mode. The default is string.

    We avoid using the escape characters and unusual atoms. "\"" is a
    legal one-character string. But we're easy on the poor client
    parser, and we make life easy for ourselves too.
*/

String Command::imapQuoted( const String & s, const QuoteMode mode )
{
    // if we're asked for an nstring, NIL may do
    if ( mode == NString && s.isEmpty() )
        return "NIL";

    // if the string is really boring and we can send an atom, we do
    if ( mode == AString && s.boring() &&
         !( s.length() == 3 && s.lower() == "nil" ) )
        return s;

    // will quoted do?
    uint i = 0;
    while ( i < s.length() &&
            s[i] >= ' ' && s[i] < 128 &&
            s[i] != '\\' && s[i] != '"' )
        i++;
    if ( i >= s.length() ) // yes
        return s.quoted( '"' );

    // well well well. literal it is.
    return "{" + fn( s.length() ) + "}\r\n" + s;
}


