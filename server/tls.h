// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef TLS_H
#define TLS_H

#include "global.h"

class EString;
class EventHandler;
class Endpoint;
class Connection;


class TlsServer
    : public Garbage
{
public:
    TlsServer( EventHandler *, const Endpoint &, const EString & );

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
