// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SASLCONNECTION_H
#define SASLCONNECTION_H

#include "connection.h"

class User;


class SaslConnection
    : public Connection
{
public:
    SaslConnection( int, Type );
    virtual ~SaslConnection();
    virtual void sendChallenge( const EString & ) = 0;

    User * user() const;
    virtual void setUser( User *, const EString & );

    void close();

    void recordAuthenticationFailure();
    void recordSyntaxError();

private:
    User * u;
    EString m;
    uint af;
    uint sf;
    uint s;
};


#endif
