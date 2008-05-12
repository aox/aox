// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mechanism.h"

#include "event.h"
#include "connection.h"
#include "configuration.h"
#include "saslconnection.h"
#include "stringlist.h"
#include "scope.h"
#include "graph.h"
#include "query.h"
#include "user.h"
#include "utf.h"

// Supported authentication mechanisms, for create().
// (Keep these alphabetical.)
#include "anonymous.h"
#include "cram-md5.h"
#include "digest-md5.h"
#include "plain.h"
#include "sasllogin.h"


class SaslData
    : public Garbage
{
public:
    SaslData()
        : state( SaslMechanism::IssuingChallenge ),
          command( 0 ), qd( false ), user( 0 ),
          l( 0 ), type( SaslMechanism::Plain ),
          connection( 0 )
    {}

    SaslMechanism::State state;
    EventHandler *command;
    bool qd;

    User * user;
    UString login;
    UString secret;
    UString storedSecret;
    Log *l;
    SaslMechanism::Type type;
    SaslConnection * connection;
};


/*! \class SaslMechanism mechanism.h
    A generic SASL authentication mechanism (RFC 2222)

    This abstract base class represents a SASL authentication mechanism.

    Each mechanism handler is implemented as a state machine, starting
    in the IssuingChallenge state, entering the AwaitingResponse state
    after a challenge() has been issued, reading the client's response
    with readResponse(), entering the Authenticating state in execute(),
    and entering either the Succeeded or Failed state when verify() is
    able to make a final decision.

    The caller is expected to retrieve and send the challenge() to the
    client when the handler is in the IssuingChallenge state; to call
    the readResponse() function when the client sends a response, and
    to call execute() to begin verification. The mechanism will call
    its owner back when it is done().

    If the mechanism supports a SASL initial response, it starts in the
    AwaitingInitialResponse state, and the caller may choose to either
    call readResponse() with the initial response, or change into the
    IssuingChallenge state and proceed as normal.

    SaslMechanism subclasses must implement challenge(), readResponse(),
    and verify(). The default implementation of challenge() and verify()
    is suitable for Anonymous and Plain authentication.

    The create() function returns a pointer to a newly-created handler
    for a named SASL authentication mechanism.
*/


/*! This static method creates and returns a pointer to a handler for
    the named \a mechanism on behalf of \a command and \a connection.
    Returns 0 if the \a mechanism is unsupported or not allowed.
    Ignores case in comparing the name.
*/

SaslMechanism * SaslMechanism::create( const String & mechanism,
                                       EventHandler * command,
                                       SaslConnection * connection )
{
    String s( mechanism.lower() );
    SaslMechanism * m = 0;

    if ( !connection->accessPermitted() )
        return 0;

    if ( s == "anonymous" )
        m = new ::Anonymous( command );
    else if ( s == "plain" )
        m = new ::Plain( command );
    else if ( s == "login" )
        m = new ::SaslLogin( command );
    else if ( s == "cram-md5" )
        m = new ::CramMD5( command );
    else if ( s == "digest-md5" )
        m = new ::DigestMD5( command );

    if ( !m )
        return 0;

    if ( !allowed( m->type(), connection->hasTls() ) ) {
        m->log( "SASL mechanism not allowed by policy: " + s );
        return 0;
    }

    Scope x( m->d->l );
    m->d->connection = connection;
    m->log( "SASL mechanism: " + s );
    return m;
}


/*! Constructs an SaslMechanism of \a type in ChallengeNeeded mode on
    behalf of \a cmd.
*/

SaslMechanism::SaslMechanism( EventHandler * cmd, Type type )
    : d( new SaslData )
{
    d->l = new Log( Log::Authentication );
    d->command = cmd;
    d->type = type;
}


/*! \fn SaslMechanism::~SaslMechanism()
    This virtual destructor exists only to facilitate safe inheritance.
*/


/*! Returns this SaslMechanism's state, which is one of the following:

    1. IssuingChallenge: Wants the server to issue another challenge().
    2. AwaitingResponse: Waiting for readResponse() to be called.
    3. Authenticating: Waiting for execute() to hear from the database.
    4. Succeeded: The authentication request succeeded.
    5. Failed: The authentication request failed.
    6. Terminated: The exchange was terminated by client request.

    The initial value is IssuingChallenge.
*/

SaslMechanism::State SaslMechanism::state() const
{
    return d->state;
}


/*! Sets this authenticator's state to \a newState. */

void SaslMechanism::setState( State newState )
{
    if ( d->state == newState )
        return;
    d->state = newState;
    switch ( newState ) {
    case AwaitingInitialResponse:
        // no logging necessary
        break;
    case IssuingChallenge:
        log( "Issuing challenge", Log::Debug );
        break;
    case AwaitingResponse:
        log( "Waiting for client response", Log::Debug );
        break;
    case Authenticating:
        log( "Verifying client response", Log::Debug );
        break;
    case Succeeded:
        log( "Authenticated: " + d->login.utf8().quoted() );
        break;
    case Failed:
        if ( d->connection )
            d->connection->recordAuthenticationFailure();
        log( "Authentication failed. Attempted login: " +
             d->login.utf8().quoted() );
        break;
    case Terminated:
        log( "Authentication terminated", Log::Debug );
        break;
    }
}


/*! This virtual function returns a challenge when the SaslMechanism is
    in IssuingChallenge mode. The caller must send the challenge to the
    client, and set the SaslMechanism to the AwaitingResponse state (so
    that reimplementations of this function don't need to).

    The return value should be a simple string, neither Base64-encoded,
    nor prefixed with "+". The default implementation is suitable for
    challenge-less authentication.
*/

String SaslMechanism::challenge()
{
    return "";
}


/*! \fn void SaslMechanism::parseResponse( const String & response )

    This pure virtual function handles a client response. \a response
    is the decoded representation of the client's response. \a
    response may contain NULs.
*/


/*! Reads an initial response from \a r, which may be 0 to indicate that
    no initial-response was supplied.
*/

void SaslMechanism::readInitialResponse( const String * r )
{
    Scope x( d->l );
    if ( r ) {
        if ( state() == AwaitingInitialResponse ) {
            if ( *r == "=" )
                parseResponse( "" );
            else
                parseResponse( r->de64() );
        }
        else {
            setState( Failed );
        }
    }
    else {
        setState( IssuingChallenge );
        execute();
    }
}


/*! Reads a response from \a r, which may be 0 to indicate that no
    response is available.
*/

void SaslMechanism::readResponse( const String * r )
{
    Scope x( d->l );
    if ( state() == AwaitingResponse ) {
        if ( !r )
            return;
        if ( *r == "*" ) {
            setState( Terminated );
            execute();
        }
        else {
            parseResponse( r->de64() );
        }
    }
    else if ( r ) {
        if ( state() != Failed )
            log( "SASL negotiation failed due to unexpected SASL response." );
        setState( Failed );
        execute();
    }
}


/*! This function expects to be called after setLogin() and
    setSecret(), which are typically called during readResponse(). It
    obtains the user's data from the database, checks the
    user-submitted password against the correct one, and enters the
    Authenticating state. It expects its parent Command to call it
    each time a Query notification occurs. It remains in the same
    state until it has enough data to make a decision.

    If the login() name does not exist, this function sets the state to
    Failed. Otherwise, it calls verify(), which is expected to validate
    the request and set the state appropriately.
*/

void SaslMechanism::execute()
{
    if ( !d->command )
        return;

    Scope x( d->l );

    if ( state() == IssuingChallenge ) {
        d->connection->sendChallenge( challenge().e64() );
        setState( AwaitingResponse );
    }

    if ( state() == AwaitingResponse )
        return;

    if ( state() == Authenticating ) {
        if ( !d->user  ) {
            d->user = new User;
            d->user->setLogin( d->login );
            d->user->refresh( this );
        }

        // Stopgap hack to block the race condition whereby the User may
        // refer to an inbox which isn't known by Mailbox.
        if ( !d->user->inbox() && d->user->state() == User::Refreshed )
            setState( Failed );
        else if ( d->user->state() == User::Nonexistent )
            setState( Failed );
        else
            d->storedSecret = d->user->secret();

        if ( d->user->id() != 0 )
            verify();
        tick();
    }

    if ( done() ) {
        d->command->execute();
        d->command = 0;
    }
}


static GraphableCounter * logins = 0;
static GraphableCounter * loginFailures = 0;
static GraphableCounter * anonLogins = 0;



/*! Calls GraphableCounter::tick() on the right object to account for
    a login failure or success. Does nothing if none of the tickers
    are appropriate.
*/

void SaslMechanism::tick()
{
    if ( d->state != Succeeded && d->state != Failed )
        return;

    if ( !logins ) {
        logins = new GraphableCounter( "successful-logins" );
        loginFailures = new GraphableCounter( "login-failures" );
        anonLogins = new GraphableCounter( "anonymous-logins" );
    }

    if ( d->state == Failed )
        loginFailures->tick();
    else if ( d->user->login() == "anonymous" &&
              Configuration::toggle( Configuration::AuthAnonymous ) )
        anonLogins->tick();
    else
        logins->tick();
}


/*! This virtual function returns true if the secret() supplied by the
    client corresponds to the storedSecret() on the server. It expects
    to be called by execute() after all relevant information has been
    obtained.

    The default implementation is suitable for Anonymous or Plain text
    authentication. It returns true if the stored secret is empty, or
    matches the client-supplied secret, or if the user is trying to
    log in as anonymous and that's permitted.
*/

void SaslMechanism::verify()
{
    if ( d->user && d->user->login() == "anonymous" ) {
        if ( Configuration::toggle( Configuration::AuthAnonymous ) )
            setState( Succeeded );
        else
            setState( Failed );
    }
    else if ( storedSecret().isEmpty() || storedSecret() == secret() ) {
        setState( Succeeded );
    }
    else {
        setState( Failed );
    }
}


/*! Returns true if this SaslMechanism has reached a final decision
    about the current authentication request.
*/

bool SaslMechanism::done() const
{
    return ( d->state == Failed || d->state == Succeeded ||
             d->state == Terminated );
}


/*! Returns the login name supplied by the client, or the empty string
    if no login has been set with setLogin().
*/

UString SaslMechanism::login() const
{
    return d->login;
}


/*! This function tells the SaslMechanism that the client supplied the
    \a name as its authorization identity. This is usually called by
    readResponse(), and the value is used by execute().
*/

void SaslMechanism::setLogin( const UString &name )
{
    d->login = name;
}


/*! Like the other setLogin(), except that it converts \a name from
    UTF-8 to unicode first. If \a name is not valid UTF-8, setLogin()
    sets the name to an empty string and logs the problem.
*/

void SaslMechanism::setLogin( const String &name )
{
    Utf8Codec u;
    d->login = u.toUnicode( name );
    if ( u.valid() )
        return;
    d->login.truncate();
    log( "Client login was not valid UTF-8: " + u.error(), Log::Error );
}


/*! Returns the secret supplied by the client, or the empty string if no
    secret has been set with setSecret().
*/

UString SaslMechanism::secret() const
{
    return d->secret;
}


/*! This function tells the SaslMechanism that the client supplied the
    \a secret with its credentials. Usually called by readResponse(),
    and the value is used by execute().
*/

void SaslMechanism::setSecret( const UString &secret )
{
    d->secret = secret;
}


/*! Like the other setSecret(), except that it converts \a secret from
    UTF-8 to unicode first. If \a secret is not valid UTF-8,
    setSecret() sets the secret to an empty string and logs the
    problem.
*/

void SaslMechanism::setSecret( const String &secret )
{
    Utf8Codec u;
    d->secret = u.toUnicode( secret );
    if ( u.valid() )
        return;
    d->secret.truncate();
    log( "Client secret was not valid UTF-8: " + u.error() );
}


/*! Returns the secret stored on the server for the login name supplied
    by the client. This function expects to be called by verify(), i.e.
    after execute() has obtained the stored secret from the database.
*/

UString SaslMechanism::storedSecret() const
{
    return d->storedSecret;
}


/*! This function is only meant to be used while testing SaslMechanism
    subclasses. It sets the stored secret to \a s, rather than waiting
    for it to be retrieved from the database by execute().
*/

void SaslMechanism::setStoredSecret( const UString &s )
{
    d->qd = true;
    d->storedSecret = s;
}


/*! \fn void SaslMechanism::setChallenge( const String & c )

    This function is only meant to be used while testing SaslMechanism
    subclasses. This implementation does nothing; if a subclass uses a
    non-default challenge(), it should also reimplement this and use
    \a c as challenge.
*/

void SaslMechanism::setChallenge( const String & )
{
}


/*! Logs message \a m with severity \a s.
*/

void SaslMechanism::log( const String &m, Log::Severity s )
{
    d->l->log( m, s );
}


/*! Returns the user logged in by this mechanism, or a null pointer if
    authentication has not succeeded (yet).
*/

User * SaslMechanism::user() const
{
    if ( state() == Succeeded )
        return d->user;
    return 0;
}


/*! Returns true if \a mechanism is currently allowed, and false if
    not. If \a privacy is true, allowed() assumes that the connection
    does not use plain-text transmission.
*/

bool SaslMechanism::allowed( Type mechanism, bool privacy )
{
    bool a = false;
    bool pt = false;
    switch( mechanism ) {
    case Anonymous:
        a = Configuration::toggle( Configuration::AuthAnonymous );
        break;
    case Plain:
        a = Configuration::toggle( Configuration::AuthPlain );
        pt = true;
        break;
    case Login:
        a = Configuration::toggle( Configuration::AuthLogin );
        pt = true;
        break;
    case CramMD5:
        a = Configuration::toggle( Configuration::AuthCramMd5 );
        break;
    case DigestMD5:
        a = Configuration::toggle( Configuration::AuthDigestMd5 );
        break;
    }

    if ( pt && !privacy ) {
        Configuration::Text p = Configuration::AllowPlaintextPasswords;
        String s = Configuration::text( p ).lower();
        if ( s == "never" )
            a = false;
        // XXX add "warn" etc. here
    }

    return a;
}


/*! Returns a list of space-separated allowed mechanisms.  If \a
    privacy is false and plain-text passwords disallowed, such
    mechanisms are not included.

    Each mechanism is prefixed by \a prefix.
*/

String SaslMechanism::allowedMechanisms( const String & prefix, bool privacy )
{
    StringList l;
    if ( allowed( Anonymous, privacy ) )
        l.append( "ANONYMOUS" );
    if ( allowed( CramMD5, privacy ) )
        l.append( "CRAM-MD5" );
    if ( allowed( DigestMD5, privacy ) )
        l.append( "DIGEST-MD5" );
    if ( allowed( Plain, privacy ) )
        l.append( "PLAIN" );
    if ( allowed( Login, privacy ) )
        l.append( "LOGIN" );
    if ( l.isEmpty() )
        return "";
    return prefix + l.join( " " + prefix );
}


/*! Returns this object's SASL type, as set by the constructor. */

SaslMechanism::Type SaslMechanism::type() const
{
    return d->type;
}


/*! Returns the canonical name of this object's SASL type, in lower
    case. For example, "cram-md5" in the case of CramMD5.
*/

String SaslMechanism::name() const
{
    String r;
    switch( d->type ) {
    case Anonymous:
        r = "anonymous";
        break;
    case Plain:
        r = "plain";
        break;
    case Login:
        r = "login";
        break;
    case CramMD5:
        r = "cram-md5";
        break;
    case DigestMD5:
        r = "digest-md5";
        break;
    }
    return r;
}
