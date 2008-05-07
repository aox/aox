// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CACHE_H
#define CACHE_H

#include "global.h"


class Cache
    : public Garbage
{
public:
    Cache();
    virtual ~Cache();

    static void clearAllCaches();

    virtual void clear() = 0;
};


#endif
