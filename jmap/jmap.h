// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef JMAP_H
#define JMAP_H

#include "event.h"
#include "estring.h"


class HTTP;
class Json;


class Jmap
    : public EventHandler
{
public:
    Jmap( HTTP * );

    void execute();

    static void setup();

private:
    void authenticate();
    void serveSession();
    void serveApi();
    void fail( uint, const EString &, const EString &,
               const EString & = "" );
    Json * call( const EString &, Json * );
    bool start( const EString &, Json *, const EString & );

private:
    class JmapData * d;
};


#endif
