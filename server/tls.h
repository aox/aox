// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef TLS_H
#define TLS_H

#include "global.h"

class String;
class EventHandler;
class Endpoint;
class Connection;


class TlsServer
    : public Garbage
{
public:
    TlsServer( EventHandler *, const Endpoint &, const String & );

    bool done() const;
    bool ok() const;

    Connection * serverSide() const;
    Connection * userSide() const;

    static void setup();

    static bool available();

private:
    class TlsServerData * d;
};


#endif
