// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FIELDCACHE_H
#define FIELDCACHE_H

#include "list.h"
#include "cache.h"
#include "header.h"

class String;
class EventHandler;


class FieldNameCache {
public:
    static void setup();
    static CacheLookup *lookup( List< String > *, EventHandler * );
    static HeaderField::Type translate( const String & );
};


#endif
