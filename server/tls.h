#ifndef TLS_H
#define TLS_H

#include "global.h"

class String;
class EventHandler;
class Endpoint;


class TlsServer
{
public:
    TlsServer( EventHandler *, const Endpoint &, const String & );

    bool done() const;
    bool ok() const;

    static void setup();

    static bool available();

private:
    class TlsServerData * d;
};


#endif
