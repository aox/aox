// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mechanism.h"
#include "event.h"
#include "query.h"
#include "configuration.h"

// Supported authentication mechanisms, for create().
// (Keep these alphabetical.)
#include "anonymous.h"
#include "cram-md5.h"
#include "digest-md5.h"
#include "plain.h"


class SaslData {
public:
    SaslData()
        : state( SaslMechanism::IssuingChallenge ),
          command( 0 ), q( 0 ), qd( false ), uid( 0 )
    {}

    SaslMechanism::State state;
    EventHandler *command;
    Query *q;
    bool qd;

    uint uid;
    String login;
    String secret;
    String storedSecret;
};


/*! \class SaslMechanism mechanism.h
    A generic SASL authentication mechanism (RFC 2222)

    This abstract base class represents a SASL authentication mechanism.

    Each mechanism handler is implemented as a state machine, starting
    in the IssuingChallenge state, entering the AwaitingResponse state
    after a challenge() has been issued, reading the client's response
    with readResponse(), entering the Authenticating state in query(),
    and entering either the Succeeded or Failed state when verify() is
    able to make a final decision.

    The caller is expected to retrieve and send the challenge() to the
    client when the handler is in the IssuingChallenge state; to call
    the readResponse() function when the client sends a response, and
    to call query() while the handler has not yet reached a decision.

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
    d->command = cmd;
}


/*! \fn SaslMechanism::~SaslMechanism()
    This virtual destructor exists only to facilitate safe inheritance.
*/


/*! Returns a pointer to the Command that created this SaslMechanism. */

EventHandler *SaslMechanism::command() const
{
    return d->command;
}


/*! Returns this SaslMechanism's state, which is one of the following:

    1. IssuingChallenge: Wants the server to issue another challenge().
    2. AwaitingResponse: Waiting for readResponse() to be called.
    3. Authenticating: Waiting for query() to hear from the database.
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


/*! This function expects to be called after setLogin() and setSecret(),
    which are typically called during readResponse(). It issues a Query
    to retrieve the record corresponding to the login() name, and enters
    the Authenticating state. It expects its parent Command to call it
    each time a Query notification occurs. It remains in the same state
    until it has enough data to make a decision.

    If the login() name does not exist, this function sets the state to
    Failed. Otherwise, it calls verify(), which is expected to validate
    the request and set the state appropriately.
*/

void SaslMechanism::query()
{
    if ( d->qd ) {
        verify();
        return;
    }

    if ( !d->q ) {
        if ( d->login.length() == 0 ) {
            setState( Failed );
            return;
        }

        setState( Authenticating );
        d->q = new Query( "select * from users where login=$1", command() );
        d->q->bind( 1, d->login );
        d->q->execute();
        return;
    }

    if ( !d->q->done() )
        return;

    if ( d->q->failed() || d->q->rows() != 1 ) {
        setState( Failed );
        return;
    }

    Row *r = d->q->nextRow();
    d->uid = r->getInt( "id" );
    d->storedSecret = r->getString( "secret" );

    verify();
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


/*! Returns the user id corresponding to login() or 0 if we don't know
    what it is yet.
*/

uint SaslMechanism::uid() const
{
    return d->uid;
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
    readResponse(), and the value is used by query().
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
    and the value is used by query().
*/

void SaslMechanism::setSecret( const String &secret )
{
    d->secret = secret;
}


/*! Returns the secret stored on the server for the login name supplied
    by the client. This function expects to be called by verify(), i.e.
    after query() has obtained the stored secret from the database.
*/

String SaslMechanism::storedSecret() const
{
    return d->storedSecret;
}


/*! This function is only meant to be used while testing SaslMechanism
    subclasses. It sets the stored secret to \a s, rather than waiting
    for it to be retrieved from the database by query().
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
