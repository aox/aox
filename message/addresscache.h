#ifndef ADDRESSCACHE_H
#define ADDRESSCACHE_H

#include "list.h"
#include "cache.h"

class Address;
class EventHandler;


class AddressCache
{
public:
    static void setup();
    static CacheLookup *lookup( List< Address > *, EventHandler * );
};


#endif
