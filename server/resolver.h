// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef RESOLVER_H
#define RESOLVER_H

#include "estringlist.h"


class Resolver
    : public Garbage
{
private:
    Resolver();

    static Resolver * resolver();
    EString readString( uint & );
    void query( uint, EStringList * );

public:
    static EStringList resolve( const EString & );
    static EStringList errors();

private:
    class ResolverData * d;
};


#endif
