// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CACHE_H
#define CACHE_H

#include "global.h"


class Cache
    : public Garbage
{
public:
    Cache( uint );
    virtual ~Cache();

    static void clearAllCaches( bool );

    virtual void clear() = 0;

private:
    uint factor;
    uint n;
};


#endif
