// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef TLSPROXY_H
#define TLSPROXY_H

#include "connection.h"


class TlsProxy: public Connection
{
public:
    TlsProxy( int );

    void react( Event );

private:
    void read();
    void parse();
    void encrypt();
    void decrypt();
    void start( TlsProxy *, const Endpoint &, const EString & );

private:
    class TlsProxyData * d;
};


#endif
