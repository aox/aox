// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FIELDCACHE_H
#define FIELDCACHE_H

#include "list.h"
#include "cachelookup.h"
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
    static void insert( const String &, uint );
};


#endif
