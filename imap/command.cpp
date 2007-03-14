// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "command.h"

#include "log.h"
#include "imap.h"
#include "user.h"
#include "buffer.h"
#include "mailbox.h"
#include "imapsession.h"
#include "messageset.h"
#include "imapparser.h"

// Keep these alphabetical.
#include "handlers/acl.h"
#include "handlers/append.h"
#include "handlers/authenticate.h"
#include "handlers/capability.h"
#include "handlers/close.h"
#include "handlers/compress.h"
#include "handlers/copy.h"
#include "handlers/create.h"
#include "handlers/delete.h"
#include "handlers/expunge.h"
#include "handlers/fetch.h"
#include "handlers/genurlauth.h"
#include "handlers/id.h"
#include "handlers/idle.h"
#include "handlers/listext.h"
#include "handlers/login.h"
#include "handlers/logout.h"
#include "handlers/lsub.h"
#include "handlers/namespace.h"
#include "handlers/noop.h"
#include "handlers/rename.h"
#include "handlers/resetkey.h"
#include "handlers/search.h"
#include "handlers/select.h"
#include "handlers/starttls.h"
#include "handlers/status.h"
#include "handlers/store.h"
#include "handlers/subscribe.h"
#include "handlers/unselect.h"
#include "handlers/urlfetch.h"
#include "handlers/view.h"

#include <sys/time.h> // gettimeofday, struct timeval


class CommandData
    : public Garbage
{
public:
    CommandData()
        : args( 0 ),
          tagged( false ),
          usesMsn( false ),
          error( false ),
          state( Command::Unparsed ), group( 0 ),
          permittedStates( 0 ),
          imap( 0 ), checker( 0 )
    {
        (void)::gettimeofday( &started, 0 );
    }

    String tag;
    String name;
    ImapParser * args;

    List< String > responses;
    String respTextCode;
    bool tagged;

    bool usesMsn;
    bool error;
    Command::State state;
    uint group;
    Command::Error errorCode;
    String errorText;

    uint permittedStates;

    struct timeval started;

    IMAP * imap;
    PermissionsChecker * checker;
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
    Executing (Command subclass working), Finished (done, but no
    response sent) or Retired (done, responses sent).

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
    Command, depending on \a name and the state of \a imap.

    \a args is a pointer to the ImapParser object for the command; it is
    expected to point to the first character after the command's \a tag
    and \a name, so that it may be used to parse any arguments. Command
    assumes ownership of \a args, which must be non-zero.

    If \a name is not a valid command, create() return a null pointer.
*/

Command * Command::create( IMAP * imap,
                           const String & tag,
                           const String & name,
                           ImapParser * args )
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
    else if ( n == "compress" )
        c = new Compress;

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
        else if ( n == "resetkey" )
            c = new ResetKey;
        else if ( n == "genurlauth" )
            c = new GenUrlauth;
        else if ( n == "urlfetch" )
            c = new UrlFetch;

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
    c->d->name = name.lower();
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

    c->setLog( new Log( Log::IMAP ) );
    c->log( "IMAP Command: " + tag + " " + name );

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


/*! Returns a pointer to the ImapParser object that was passed to this
    Command's constructor. May not be 0.
*/

ImapParser * Command::parser() const
{
    return d->args;
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
    case Retired:
        break;
    case Unparsed:
        // this is the initial state, it should never be called.
        break;
    case Blocked:
        log( "Deferring execution", Log::Debug );
        break;
    case Executing:
        (void)::gettimeofday( &d->started, 0 );
        log( "Executing", Log::Debug );
        break;
    case Finished:
        struct timeval end;
        (void)::gettimeofday( &end, 0 );
        long elapsed =
            ( end.tv_sec - d->started.tv_sec ) * 1000000 +
            ( end.tv_usec - d->started.tv_usec );
        Log::Severity level = Log::Debug;
        if ( elapsed > 3000 )
            level = Log::Info;
        String m;
        m.append( "Execution time " );
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


/*! Returns the tag of this command. Useful for logging. */

String Command::tag() const
{
    return d->tag;
}


/*! Returns the name of this command, e.g. 'uid fetch', in lower
    case. */

String Command::name() const
{
    return d->name;
}


/*! Returns true if this command has parsed at least one MSN, and
    false if it has not (ie. it returns false before parse()).
*/

bool Command::usesMsn() const
{
    return d->usesMsn;
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


/*! Sets this Command's state to ::Finished and emit any queued
    responses as soon as possible.
*/

void Command::finish()
{
    setState( Finished );
    emitResponses();
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
    if ( state() == Retired )
        return;

    Session * s = imap()->session();
    if ( s && !s->initialised() )
        return;

    if ( !d->tagged ) {
        if ( !d->error ) {
            if ( d->respTextCode.isEmpty() )
                respond( "OK done", Tagged );
            else
                respond( "OK [" + d->respTextCode + "] done", Tagged );
        }
        else {
            if ( d->errorCode == Bad )
                respond( "BAD " + d->errorText, Tagged );
            else
                respond( "NO " + d->errorText, Tagged );
        }
    }

    List< String >::Iterator it( d->responses );
    while ( it ) {
        String * r = it;
        ++it;
        if ( s && !it )
            s->emitResponses();
        imap()->enqueue( *r );
        if ( !it ) {
            int i = r->find( ' ' );
            if ( i >= 0 )
                log( "Result: " + r->mid( i+1 ) );
        }
    }

    setState( Retired );
    imap()->write();
}


/*! Returns the next, unparsed character, without consuming
    it. Returns 0 in case of error, but does not emit any error
    messages.
*/

char Command::nextChar()
{
    return d->args->nextChar();
}


/*! Steps past \a n characters of the unparsed arguments. */

void Command::step( uint n )
{
    d->args->step( n );
}


/*! Checks whether the next characters in the input match \a s. If so,
    present() steps past the matching characters and returns true. If
    not, it returns false without changing the input.

    Note that the match is completely case insensitive.
*/

bool Command::present( const String & s )
{
    return d->args->present( s );
}


/*! Verifies that the next characters in the input match \a s (case
    insensitively), and removes whatever matches. If input isn't as
    required, require() calls error().
*/

void Command::require( const String & s )
{
    d->args->require( s );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
}


/*! Parses from \a min to \a max digits and returns them in string
    form. If fewer than \a min digits are available, error() is called.
*/

String Command::digits( uint min, uint max )
{
    String r( d->args->digits( min, max ) );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r;
}


/*! Parses from \a min to \a max letters and returns them in string
    form. If fewer than \a min letters are available, error() is
    called.
*/

String Command::letters( uint min, uint max )
{
    String r( d->args->letters( min, max ) );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r;
}


/*! Checks that the atom "nil" is next at the parse position, and
    steps past. */

void Command::nil()
{
    d->args->nil();
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
}


/*! Checks that a single space is next at the parse position, and
    steps past it if all is ok.

    This command accepts more than one space, and gives a
    warning. This is to tolerate broken clients, while giving client
    authors a strong hint.
*/

void Command::space()
{
    d->args->require( " " );
    if ( d->args->nextChar() != ' ' )
        return;

    while ( d->args->nextChar() == ' ' )
        d->args->step();
    respond( "BAD Illegal space seen before this text: " + following(),
             Untagged );
}


/*! Parses a single number and returns it. */

uint Command::number()
{
    uint n = d->args->number();
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return n;
}


/*! Parses a single nzNumber and returns it. */

uint Command::nzNumber()
{
    uint n = d->args->nzNumber();
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return n;
}


/*! Parses an IMAP atom and returns it as a string. Calls error() and
    turns an empty string in case of error.
*/

String Command::atom()
{
    String r( d->args->atom() );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r;
}


/*! Parses one or more consecutive list-chars (ATOM-CHAR/list-wildcards/
    resp-specials) and returns them as a String. Calls error() and
    returns an empty string in case of error.
*/

String Command::listChars()
{
    String r( d->args->atom() );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r;
}


/*! Parses an IMAP quoted string and return the relevant string. In
    case of error an empty string is returned.

    Note that any character can be quoted. IMAP properly allows only
    the quote character and the backslash to be quoted. In this
    respect, we deviate from the standard.
*/

String Command::quoted()
{
    String r( d->args->quoted() );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r;
}


/*! Parses an IMAP literal and returns the relevant string. Returns an
    empty string in case of error.
*/

String Command::literal()
{
    String r( d->args->literal() );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r;
}


/*! Parses an IMAP string and returns it. If there is none, error() is
    called appropriately.
*/

String Command::string()
{
    String r( d->args->string() );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r;
}


/*! Parses an IMAP nstring and returns that string. If the nstring is
    NIL, an empty string is returned and error() is called.
*/

String Command::nstring()
{
    String r( d->args->nstring() );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r;
}


/*! Parses an IMAP astring and returns that string. In case of error,
    astring() calls error() appropriately and returns an empty string.
*/

String Command::astring()
{
    String r( d->args->astring() );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r;
}


/*! Parses and returns a list-mailbox. This is the same as an atom(),
    except that the three additional characters %, * and ] are
    accepted.

    The return value is lowercased, because our mailbox names are case
    insensitive.
*/

String Command::listMailbox()
{
    String r( d->args->listMailbox() );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r.lower();
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
    return result;
}



/*! Shrinks \a set by removing expunged and nonexistent UIDs. Quiet:
    Does not emit any kind of error or response.
*/

void Command::shrink( MessageSet * set )
{
    ImapSession * s = imap()->session();
    if ( !s || !set || set->isEmpty() )
        return;

    set->remove( s->expunged() );
    *set = set->intersection( s->messages() );
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

    d->usesMsn = true;

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
    String r( d->args->flag() );
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
    return r;
}


/*! Asserts that the end of parsing has been reached. If the IMAP
    client has supplied more text, that text is a parse error and
    results in a BAD response.
*/

void Command::end()
{
    d->args->end();
    if ( !d->args->ok() )
        error( Bad, d->args->error() );
}


/*! This private utility function returns a const string of no more
    than 15 characters containing the first unparsed bits of input.
*/

const String Command::following() const
{
    return d->args->following();
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


/*! Returns the Mailbox corresponding to \a name. This is a
    convenience function that really wraps User::mailboxName().
*/

class Mailbox * Command::mailbox( const String & name ) const
{
    return Mailbox::find( mailboxName( name ) );
}


/*! Returns the canonical name of the mailbox to which \a name
    refers. This is a convenience function that really wraps
    User::mailboxName().
*/

String Command::mailboxName( const String & name ) const
{
    User * u = imap()->user();
    if ( !u )
        return "";
    return u->mailboxName( name );
}


/*! Notes that this command requires \a r on \a m. execute() should
    proceed only if and when permitted() is true.
*/

void Command::requireRight( Mailbox * m, Permissions::Right r )
{
    if ( !d->checker )
        d->checker = new PermissionsChecker;

    Permissions * p = 0;
    if ( imap()->state() == IMAP::Selected && m == imap()->session()->mailbox() )
        p = imap()->session()->permissions();
    else
        p = d->checker->permissions( m, imap()->user() );
    if ( !p )
        p = new Permissions( m, imap()->user(), this );

    d->checker->require( p, r );
}


/*! Returns true if this command is permitted to proceed, and false if
    it either must abort due to lack of rights or wait until
    Permissions has fetched more information.

    If permitted() denies permission, it also sets a suitable error
    message.
*/

bool Command::permitted()
{
    if ( !d->checker )
        return false;
    if ( !d->checker->ready() )
        return false;
    if ( d->checker->allowed() )
        return true;
    error( No, d->checker->error().simplified() );
    return false;
}


/*! Returns true if all permission checking could be carried out, and
    false if at least one Permissions object is still working.
*/

bool Command::permissionChecked() const
{
    if ( d->checker && !d->checker->ready() )
        return false;
    return true;
}


/*! Remembers that when the time comes to send a tagged OK, \a s
    should be sent as resp-text-code. \a s should not contain [],
    emitResponses() adds those itself.
*/

void Command::setRespTextCode( const String & s )
{
    d->respTextCode = s;
}


#if 0
/* By convention, international mailbox names in IMAP4rev1 are specified
   using a modified version of the UTF-7 encoding described in [UTF-7].
   Modified UTF-7 may also be usable in servers that implement an
   earlier version of this protocol.

   In modified UTF-7, printable US-ASCII characters, except for "&",
   represent themselves; that is, characters with octet values 0x20-0x25
   and 0x27-0x7e.  The character "&" (0x26) is represented by the
   two-octet sequence "&-".

   All other characters (octet values 0x00-0x1f and 0x7f-0xff) are
   represented in modified BASE64, with a further modification from
   [UTF-7] that "," is used instead of "/".  Modified BASE64 MUST NOT be
   used to represent any printing US-ASCII character which can represent
   itself.

   "&" is used to shift to modified BASE64 and "-" to shift back to
   US-ASCII.  There is no implicit shift from BASE64 to US-ASCII, and
   null shifts ("-&" while in BASE64; note that "&-" while in US-ASCII
   means "&") are not permitted.  However, all names start in US-ASCII,
   and MUST end in US-ASCII; that is, a name that ends with a non-ASCII
   ISO-10646 character MUST end with a "-").

   Although modified UTF-7 is a convention, it establishes certain
   requirements on server handling of any mailbox name with an
   embedded "&" character.  In particular, server implementations MUST
   preserve the exact form of the modified BASE64 portion of a
   modified UTF-7 name and treat that text as case-sensitive, even if
   names are otherwise case-insensitive or case-folded.

   Server implementations SHOULD verify that any mailbox name with an
   embedded "&" character, used as an argument to CREATE, is: in the
   correctly modified UTF-7 syntax, has no superfluous shifts, and has
   no encoding in modified BASE64 of any printing US-ASCII character
   which can represent itself.  However, client implementations MUST
   NOT depend upon the server doing this, and SHOULD NOT attempt to
   create a mailbox name with an embedded "&" character unless it
   complies with the modified UTF-7 syntax.

   Server implementations which export a mail store that does not
   follow the modified UTF-7 convention MUST convert to modified UTF-7
   any mailbox name that contains either non-ASCII characters or the
   "&" character.

        For example, here is a mailbox name which mixes English,
        Chinese, and Japanese text: ~peter/mail/&U,BTFw-/&ZeVnLIqe-

        For example, the string "&Jjo!" is not a valid mailbox name
        because it does not contain a shift to US-ASCII before the
        "!".  The correct form is "&Jjo-!".  The string
        "&U,BTFw-&ZeVnLIqe-" is not permitted because it contains a
        superfluous shift.  The correct form is "&U,BTF2XlZyyKng-".
*/

/*! Returns a version of input where modified UTF-7 has been
    undone.

    The return value is in UTF-8. Wouldn't it be better to use
    UString?
*/

String Command::deMUtf7( const String & )
{

}


/*! Returns a version of input which has been converted from UTF-8
    to mUTF-7.
*/

String Command::mUtf7( const String & )
{

}
#endif
