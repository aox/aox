// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LDAPRELAY_H
#define LDAPRELAY_H

#include "connection.h"


class SaslMechanism;


class LdapRelay
    : public Connection
{
public:
    LdapRelay( SaslMechanism * );

    void react( Event );

    enum State { Working,
                 BindFailed,
                 BindSucceeded };

    State state() const;

    String challenge();
    String setResponse( const String & );

    static Endpoint server();

    void parse();
    void bind();

private:
    class LdapRelayData * d;

    void fail( const String & );
    void succeed();
};


#endif
