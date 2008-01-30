// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sasllogin.h"


/*! \class SaslLogin sasllogin.h
    Implement SASL LOGIN authentication.

    LOGIN is a non-standard SASL authentication mechanism, described in
    the now-abandoned draft-murchison-sasl-login-*.txt

    We issue the standard "User Name" and "Password" challenges, not the
    permitted alternative "Username:" and "Password:".

    (This class is not named just "Login" because of the IMAP command of
    the same name.)
*/


/*! Creates a new SaslLogin object on behalf of \a c. */

SaslLogin::SaslLogin( EventHandler * c )
    : SaslMechanism( c, SaslMechanism::Login )
{
}


String SaslLogin::challenge()
{
    if ( login().isEmpty() )
        return "Username:";
    else
        return "Password:";
}


void SaslLogin::parseResponse( const String &s )
{
    if ( login().isEmpty() ) {
        if ( s.isEmpty() ) {
            setState( Failed );
        }
        else {
            setLogin( s );
            setState( IssuingChallenge );
        }
    }
    else {
        setSecret( s );
        setState( Authenticating );
    }
    execute();
}
