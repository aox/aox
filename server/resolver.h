// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef RESOLVER_H
#define RESOLVER_H

#include "stringlist.h"


class Resolver
    : public Garbage
{
private:
    Resolver();

    static Resolver * resolver();
    String readString( uint & );
    void query( uint, StringList * );

public:
    static StringList resolve( const String & );
    static StringList errors();

private:
    class ResolverData * d;
};


#endif
