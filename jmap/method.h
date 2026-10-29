// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef METHOD_H
#define METHOD_H

#include "event.h"
#include "estring.h"


class Json;
class User;


class JmapMethod
    : public EventHandler
{
public:
    JmapMethod( EventHandler *, User *, Json * );

    bool done() const;
    Json * response() const;
    EString responseName() const;

protected:
    Json * arguments() const;
    User * user() const;
    void respond( const EString &, Json * );
    void fail( const EString & );
    bool checkAccount();

private:
    class JmapMethodData * d;
};


#endif
