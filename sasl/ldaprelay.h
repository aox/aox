// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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

    static Endpoint server();

    void parse();
    void bind();
    void unbind();

private:
    class LdapRelayData * d;

    void fail( const EString & );
    void succeed();
};


#endif
