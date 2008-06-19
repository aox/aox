// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "ldap.h"


/*! \class LdapRelay ldaprelay.h

    The LdapRelay class helps Mechanism relay SASL challenges and
    responses to and from an LDAP server. If the LDAP server accepts
    the authentication, then the user is accepted as an Archiveopteryx
    user.

    The LdapRelay state machine contains the following states:
    
    Connecting: The LDAP server still hasn't answered.
    
    Timeout: The LDAP server didn't answer in time (either didn't
    accept the connection or didn't answer a bind request).

    ConnectionRefused: The LDAP server refused our connection.

    MechanismRejected: The LDAP server refused to use the SASL
    mechanism we've been told to use.
    
    BindFailed: We should reject this authentication.

    BindSucceeded: We should accept this authentication.

    ChallengeAvailable: A challenge has been received from the LDAP
    server and can be reformatted and sent to the client.
    
    WaitingForResponse: We've received the LDAP server's challenge,
    but still doin't have the data needed to respond to it.
    
    WaitingForChallenge: We've sent a response to the LDAP server, but
    haven't received any news from the LDAP server.
*/



/*! Constructs an empty

*/

LdapRelay::LdapRelay()
    : Connection( Connection::LdapRelay ),d ( new LdapRelayData )
{
    connect( Endpoint(
                 Configuration::text( Configuration::LdapServerAddress ),
                 Configuration::toggle( Configuration::LdapServerPort ) ) );
}


/*! Reacts to incoming packets from the LDAP server, changes the
    object's state, and relays data to and from the Mechanism.
*/

void LdapRelay::react( Event e )
{
    case Read:
        delete d->timeout;
        d->timeout = 0;
        parse();
        break;

    case Timeout:
        d->state = Timeout;
        Connection::setState( Closing );
        d->mechanism->execute();
        break;

    case Connect:
        d->state = Connected;
        d->mechanism->execute();
        break;

    case Error:
    case Close:
        if ( state() != Logout && Connection::state() != Closing )
            log( "Unexpected close by LDAP server" );
        break;

    case Shutdown:
        break;
    }
}
