#ifndef TLSPROXY_H
#define TLSPROXY_H

#include "connection.h"


class TlsProxy: public Connection
{
public:
    TlsProxy( int );

    void react( Event );

private:
    void parse();
    void encrypt();
    void decrypt();
    void start( TlsProxy *, const Endpoint &, const String & );

private:
    class TlsProxyData * d;
};


#endif
