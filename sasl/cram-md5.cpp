// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cram-md5.h"

#include "string.h"
#include "entropy.h"
#include "md5.h"
#include "configuration.h"

#include <time.h>


/*! \class CramMD5 cram-md5.h
    Implements CRAM-MD5 authentication (RFC 2195)

    We issue a challenge, and expect the client to respond with username
    and the HMAC-MD5 digest of the challenge keyed with a shared secret.
    We accept the request only if the digest matches our re-computation
    based on the stored secret from the database.
*/


CramMD5::CramMD5( EventHandler *c )
    : SaslMechanism( c )
{
}


String CramMD5::challenge()
{
    uint t = time(0);

    uint r = 10000;
    while ( r > 9999 )
        r = Entropy::asNumber( 2 ) % 16384;

    String hn = Configuration::hostname();
    if ( hn.isEmpty() )
        hn = "oryx.invalid";

    challengeSent = "<" + fn( r ) + "." + fn( t ) + "@" + hn + ">";

    /* draft-ietf-sasl-crammd5-02 specifies the above challenge format,
       but Lyndon Nerenberg says that the next revision will specify an
       opaque random string, probably like the following:

    challengeSent = "<" + Entropy::asString( 12 ).e64() +
                    "@" + Configuration::hostname() + ">";
    */

    return challengeSent;
}


void CramMD5::readResponse( const String &s )
{
    int i;

    i = s.find( ' ' );
    while ( s.find( ' ', i+1 ) > i )
        i = s.find( ' ', i+1 );

    if ( i <= 0 ) {
        log( "Syntax error in client response", Log::Error );
        setState( Failed );
        return;
    }

    setLogin( s.mid( 0, i ) );
    setSecret( s.mid( i+1, s.length()-i ).lower() );
}


void CramMD5::verify()
{
    if ( secret() == MD5::HMAC( storedSecret(), challengeSent ).hex() )
        setState( Succeeded );
    else
        setState( Failed );
}


void CramMD5::setChallenge( const String &s )
{
    challengeSent = s;
}


