// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FIELDCACHE_H
#define FIELDCACHE_H

#include "list.h"
#include "cache.h"
#include "header.h"


class String;
class Transaction;
class EventHandler;


class FieldNameCache
    : public Garbage
{
public:
    static void setup();
    static CacheLookup *lookup( Transaction *, List< String > *,
                                EventHandler * );
    static uint translate( const String & );
};


#endif
