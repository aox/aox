// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LDAPRELAY_H
#define LDAPRELAY_H

#include "connection.h"


class LdapRelay
    : public Connection
{
public:
    LdapRelay();

    void react( Event );

    enum State { Connecting,
                 Timeout,
                 ConnectionRefused,
                 MechanismRejected,
                 BindFailed,
                 BindSucceeded,
                 ChallengeAvailable,
                 WaitingForResponse,
                 WaitingForChallenge );

    State state() const;

    String challenge();
    String setResponse( const String & );
};


#endif
