// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

/*! \class Plain plain.h
    Implements plain-text authentication (RFC 2595 section 6)

    SASL permits a distinction between the authentication ID (which
    credentials are checked) and the authorization ID (which is logged
    in). This class firmly insists that the two be the same.

    Note that there is also a different, incompatible plain-text
    mechanism offered by some servers and supported by some clients
    "AUTH=LOGIN", implemented by SaslLogin.
*/

#include "plain.h"

#include "stringlist.h"


/*! Creates a plain-text SASL authentication object on behalf of \a c */

Plain::Plain( EventHandler *c )
    : SaslMechanism( c, SaslMechanism::Plain )
{
    setState( AwaitingInitialResponse );
}


void Plain::parseResponse( const String & response )
{
    String authorizeId;
    String authenticateId;
    String secret;

    bool ok = parse( authorizeId, authenticateId, secret, response );
    if ( !ok || authenticateId != authorizeId ) {
        setState( Failed );

        if ( !ok )
            log( "PLAIN: Parse error for (?)", Log::Error );
        else
            log( "PLAIN: Client supplied two identities: " +
                 authenticateId.quoted() + ", " + 
                 authorizeId.quoted(), Log::Error );
        return;
    }

    setState( Authenticating );
    setLogin( authenticateId );
    setSecret( secret );
    execute();
}


/*! Parses an AUTH=PLAIN \a response to extract the \a authenticateId,
    \a authorizeId, and \a pw.
*/

bool Plain::parse( String & authorizeId, String & authenticateId,
                   String & pw, const String & response )
{
    StringList * l = StringList::split( 0, response );
    if ( !l || l->count() != 3 )
        return false;

    StringList::Iterator i( l );
    authorizeId = *i;
    ++i;
    authenticateId = *i;
    ++i;
    pw = *i;

    if ( authenticateId.isEmpty() || pw.isEmpty() )
        return false;

    if ( authorizeId.isEmpty() )
        authorizeId = authenticateId;

    return true;
}
