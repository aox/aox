// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
    virtual void recordSyntaxError();
    uint syntaxErrors();

private:
    User * u;
    EString m;
    uint af;
    uint sf;
    uint s;
    bool logged;
};


#endif
