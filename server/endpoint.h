#ifndef ENDPOINT_H
#define ENDPOINT_H

#include "global.h"

class String;


class Endpoint {
public:
    Endpoint();
    Endpoint( const Endpoint & );
    Endpoint( const String &, uint );
    Endpoint( const struct sockaddr * );

    enum Protocol { IPv4, IPv6 };

    bool valid() const;
    Protocol protocol() const;
    String address() const;
    uint port() const;

    struct sockaddr *sockaddr() const;
    uint sockaddrSize() const;

    String string() const;

    Endpoint & operator=( const Endpoint & );

private:
    class EndpointData * d;
};

#endif
