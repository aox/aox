// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

/*! \class Plain plain.h
    Implements plain-text authentication (RFC 2595 section 6)

    SASL permits a distinction between the authentication ID (which
    credentials are checked) and the authorization ID (which is logged
    in). This class firmly insists that the two be the same.

    (Note that there is also a different, incompatible plain-text
    mechanism offered by some servers and supported by some clients,
    "AUTH=LOGIN". We don't support that, because there's no usable
    specification for it and the implementations vary significantly,
    probably incompatibly. See
    http://www.washington.edu/imap/listarch/1999/msg00078.html for
    details.)
*/

#include "plain.h"


Plain::Plain( EventHandler *c )
    : SaslMechanism( c )
{
    setState( AwaitingInitialResponse );
}


void Plain::readResponse( const String & response )
{
    String authenticateId;
    String authorizeId;
    String secret;

    bool ok = parse( authenticateId, authorizeId, secret, response );
    if ( !ok || authenticateId != authorizeId ) {
        setState( Failed );

        if ( !ok )
            log( "PLAIN: Parse error for (?)", Log::Error );
        else
            log( "PLAIN: Client supplied two identities: '"+
                 authenticateId+"', '"+authorizeId+"'", Log::Error );
        return;
    }

    setLogin( authorizeId );
    setSecret( secret );
}


/*! Parses an AUTH=PLAIN \a response to extract the \a authenticateId,
    \a authorizeId, and \a pw.
*/

bool Plain::parse( String & authenticateId,
                   String & authorizeId,
                   String & pw,
                   const String & response )
{
    uint i = response.length();
    uint j = UINT_MAX;
    int m = 0;

    authenticateId.truncate( 0 );
    authorizeId.truncate( 0 );
    pw.truncate( 0 );

    while ( i > 0 ) {
        i--;
        if ( i == 0 || response[i-1] == 0 ) {
            String s = response.mid( i, j-i-1 );
            if ( m == 0 )
                pw = s;
            else if ( m == 1 )
                authorizeId = s;
            else if ( m == 2 )
                authenticateId = s;
            else
                return false;
            j = i;
            m++;
        }
    }

    if ( m < 2 )
        return false;

    if ( authenticateId.isEmpty() )
        authenticateId = authorizeId;

    if ( authenticateId.length() < 1 ||
         authorizeId.length() < 1 ||
         pw.length() < 1 )
        return false;

    return true;
}


