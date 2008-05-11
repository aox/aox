// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "saslconnection.h"

#include "user.h"
#include "query.h"
#include "string.h"
#include "endpoint.h"
#include "eventloop.h"

// time
#include <time.h>


/*! \class SaslConnection connection.h
    A connection that can engage in a SASL negotiation.
*/

/*! Creates an Inactive \a type connection using \a fd. */

SaslConnection::SaslConnection( int fd, Type type )
    : Connection( fd, type )
{
}


/*! Obligatory virtual destructor. */

SaslConnection::~SaslConnection()
{
}


/*! \fn virtual void SaslConnection::sendChallenge( const String & s ) = 0

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

void SaslConnection::setUser( User * user, const String & mechanism )
{
    u = user;
    m = mechanism;
    s = (uint)time(0);
}


/*! This reimplementation only adds a record to the connections table.

    If the connection is closed as part of server shutdown, then it's
    probably too late to execute a new Query. We're tolerant of that.
*/

void SaslConnection::close()
{
    if ( state() == Invalid )
        return;
    String client = peer().string();
    Connection::close();

    if ( !u )
        return;

    if ( EventLoop::global()->inShutdown() ) {
        log( "Cannot log connection in the connections table",
             Log::Info );
        return;
    }

    Query * q = new Query(
        "insert into connections "
        "(userid,client,mechanism,authfailures,syntaxerrors,started_at,ended_at) "
        "values ($1,$2,$3,$4,$5,"
        "$6::interval + 'epoch'::timestamptz,"
        "$7::interval + 'epoch'::timestamptz)", 0
    );

    q->bind( 1, u->id() );
    q->bind( 2, client );
    q->bind( 3, m );
    q->bind( 4, af );
    q->bind( 5, sf );
    q->bind( 6, s );
    q->bind( 7, (uint)time( 0 ) );
    q->execute();
}


/*! Used to count authentication failures for logging and
    statistics.
*/

void SaslConnection::recordAuthenticationFailure()
{
    af++;
}


/*! Used to count protocol syntax errors for logging and
    statistics.
*/

void SaslConnection::recordSyntaxError()
{
    sf++;
}
