// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "saslconnection.h"

#include "ustring.h"

#include "user.h"
#include "query.h"
#include "estring.h"
#include "endpoint.h"
#include "eventloop.h"

// time
#include <time.h>


/*! \class SaslConnection saslconnection.h
    A connection that can engage in a SASL negotiation.
*/

/*! Creates an Inactive \a type connection using \a fd. */

SaslConnection::SaslConnection( int fd, Type type )
    : Connection( fd, type ),
      u( 0 ), af( 0 ), sf( 0 ), s( 0 ), logged( false )
{
}


/*! Obligatory virtual destructor. */

SaslConnection::~SaslConnection()
{
}


/*! \fn virtual void SaslConnection::sendChallenge( const EString & s ) = 0

    This virtual function must be defined by SaslConnection subclasses.
    It is called by a SaslMechanism to send the challenge \a s, and is
    responsible for enqueue()ing a correctly-encoded version of it.
*/


/*! Returns a pointer to the authenticated User for this Connection, or
    0 if a user has not yet been authenticated.
*/

User * SaslConnection::user() const
{
    return u;
}


/*! Informs this Connection that \a user has been authenticated using
    the named \a mechanism. After a call to this function, user() will
    return the specified \a user.
*/

void SaslConnection::setUser( User * user, const EString & mechanism )
{
    u = user;
    m = mechanism;
    s = (uint)time(0);
}


/*! This reimplementation logs the connection in the connections table
    and cancels any other queries still running.

    If the connection is closed as part of server shutdown, then it's
    probably too late to execute a new Query. We're tolerant of that.
*/

void SaslConnection::close()
{
    Endpoint client = peer();
    Connection::close();

    if ( !u || logged ||
         !client.valid() || client.protocol() == Endpoint::Unix )
        return;

    logged = true;

    Query * q = new Query(
        "insert into connections "
        "(username,address,port,mechanism,authfailures,"
        "syntaxerrors,started_at,ended_at,userid) "
        "values ($1,$2,$3,$4,$5,$6,"
        "$7::interval + 'epoch'::timestamptz,"
        "$8::interval + 'epoch'::timestamptz,$9)", 0
    );

    q->bind( 1, u->login() );
    q->bind( 2, client.address() );
    q->bind( 3, client.port() );
    q->bind( 4, m );
    q->bind( 5, af );
    q->bind( 6, sf );
    q->bind( 7, s );
    q->bind( 8, (uint)time( 0 ) );
    q->bind( 9, u->id() );
    q->execute();

}


/*! Counts authentication failures for logging and statistics,
    and logs that \a login failed, with the client address.

    The log line is designed for fail2ban.
*/

void SaslConnection::recordAuthenticationFailure( const UString & login )
{
    af++;
    log( "Authentication failed for " + login.utf8().quoted() +
         " from " + peer().address(), Log::Significant );
}


/*! Counts protocol syntax errors for logging and statistics,
    and logs errors the ones that happen before anyone has logged in, with
    the address, so that systems like fail2ban can act appropriately.
*/

void SaslConnection::recordSyntaxError()
{
    sf++;
    if ( !u )
        log( "Protocol error from " + peer().address() +
             ", unauthenticated", Log::Significant );
}


/*! Returns the number of syntax errors seen so far. */

uint SaslConnection::syntaxErrors()
{
    return sf;
}
