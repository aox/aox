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
    http://web.archive.org/web/20030117014240/http://www.washington.edu/imap/listarch/1999/msg00078.html
    for details.)
*/

#include "plain.h"

/*! Creates a plain-text SASL authentication object on behalf of \a c */

Plain::Plain( EventHandler *c )
    : SaslMechanism( c, SaslMechanism::Plain )
{
    setState( AwaitingInitialResponse );
}


void Plain::readResponse( const String & response )
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
            log( "PLAIN: Client supplied two identities: '"+
                 authenticateId+"', '"+authorizeId+"'", Log::Error );
        return;
    }

    setLogin( authenticateId );
    setSecret( secret );
}


/*! Parses an AUTH=PLAIN \a response to extract the \a authenticateId,
    \a authorizeId, and \a pw.
*/

bool Plain::parse( String & authorizeId, String & authenticateId,
                   String & pw, const String & response )
{
    authorizeId.truncate( 0 );
    authenticateId.truncate( 0 );
    pw.truncate( 0 );

    int m = 0;
    uint i = 0;
    uint last = 0;

    while ( i <= response.length() ) {
        if ( response[i] == '\0' ) {
            String s = response.mid( last, i-last );
            last = i+1;
            if ( m == 0 )
                authorizeId = s;
            else if ( m == 1 )
                authenticateId = s;
            else if ( m == 2 )
                pw = s;
            else
                return false;
            m++;
        }
        i++;
    }

    if ( m < 2 )
        return false;

    if ( authorizeId.isEmpty() )
        authorizeId = authenticateId;

    if ( authorizeId.length() < 1 ||
         authenticateId.length() < 1 ||
         pw.length() < 1 )
        return false;

    return true;
}
