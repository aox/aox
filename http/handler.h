// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef HANDLER_H
#define HANDLER_H

#include "global.h"
#include "estring.h"


class HTTP;


class HttpHandler
    : public Garbage
{
public:
    HttpHandler( const EString & );
    virtual ~HttpHandler() {}

    EString path() const;
    virtual void handle( HTTP * ) = 0;

    static HttpHandler * find( const EString & );

private:
    EString p;
};


#endif
