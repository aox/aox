// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mechanism.h"
#include "event.h"
#include "query.h"
#include "configuration.h"
#include "user.h"

// Supported authentication mechanisms, for create().
// (Keep these alphabetical.)
#include "anonymous.h"
#include "cram-md5.h"
#include "digest-md5.h"
#include "plain.h"


class SaslData
    : public Garbage
{
public:
    SaslData()
        : state( SaslMechanism::IssuingChallenge ),
          command( 0 ), qd( false ), user( 0 ),
          l( 0 )
    {}

    SaslMechanism::State state;
    EventHandler *command;
    bool qd;

    User * user;
    String login;
    String secret;
    String storedSecret;
    Log *l;
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
    the named \a mechanism on behalf of \a command. Returns 0 if the
    \a mechanism is unsupported. Ignores case in comparing the name.
*/

SaslMechanism *SaslMechanism::create( const String &mechanism,
                                      EventHandler *command )
{
    String s( mechanism.lower() );

    if ( s == "anonymous" )
        return new Anonymous( command );
    else if ( s == "plain" )
        return new Plain( command );
    else if ( s == "cram-md5" )
        return new CramMD5( command );
    else if ( s == "digest-md5" )
        return new DigestMD5( command );
    return 0;
}


/*! Constructs an SaslMechanism in ChallengeNeeded mode on behalf of
    \a cmd.
*/

SaslMechanism::SaslMechanism( EventHandler *cmd )
    : d( new SaslData )
{
    d->l = new Log( Log::Authentication );
    d->command = cmd;
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

    The initial value is IssuingChallenge.
*/

SaslMechanism::State SaslMechanism::state() const
{
    return d->state;
}


/*! Sets this authenticator's state to \a newState. */

void SaslMechanism::setState( State newState )
{
    d->state = newState;
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


/*! \fn void SaslMechanism::readResponse( const String & response )

    This pure virtual function handles a client response. \a response
    is the decoded representation of the client's response. \a
    response may contain NULs.
*/


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
    if ( done() )
        return;

    if ( !d->user ) {
        setState( Authenticating );
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

    if ( state() == Authenticating && d->user->state() != User::Unverified )
        verify();

    if ( done() )
        d->command->execute();
}


/*! This virtual function returns true if the secret() supplied by the
    client corresponds to the storedSecret() on the server. It expects
    to be called by verify() after all relevant information has been
    obtained.

    The default implementation is suitable for Anonymous or Plain text
    authentication. It returns true if the stored secret is empty, or
    matches the client-supplied secret.
*/

void SaslMechanism::verify()
{
    if ( storedSecret().isEmpty() || storedSecret() == secret() )
        setState( Succeeded );
    else
        setState( Failed );
}


/*! Returns true if this SaslMechanism has reached a final decision
    about the current authentication request.
*/

bool SaslMechanism::done() const
{
    return ( d->state == Failed || d->state == Succeeded );
}


/*! Returns the login name supplied by the client, or the empty string
    if no login has been set with setLogin().
*/

String SaslMechanism::login() const
{
    return d->login;
}


/*! This function tells the SaslMechanism that the client supplied the
    \a name as its authorization identity. This is usually called by
    readResponse(), and the value is used by execute().
*/

void SaslMechanism::setLogin( const String &name )
{
    d->login = name;
}


/*! Returns the secret supplied by the client, or the empty string if no
    secret has been set with setSecret().
*/

String SaslMechanism::secret() const
{
    return d->secret;
}


/*! This function tells the SaslMechanism that the client supplied the
    \a secret with its credentials. Usually called by readResponse(),
    and the value is used by execute().
*/

void SaslMechanism::setSecret( const String &secret )
{
    d->secret = secret;
}


/*! Returns the secret stored on the server for the login name supplied
    by the client. This function expects to be called by verify(), i.e.
    after execute() has obtained the stored secret from the database.
*/

String SaslMechanism::storedSecret() const
{
    return d->storedSecret;
}


/*! This function is only meant to be used while testing SaslMechanism
    subclasses. It sets the stored secret to \a s, rather than waiting
    for it to be retrieved from the database by execute().
*/

void SaslMechanism::setStoredSecret( const String &s )
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
