#ifndef ADDRESSCACHE_H
#define ADDRESSCACHE_H

#include "list.h"

class Address;
class EventHandler;


class AddressCache
{
public:
    static void setup();
    static void lookup( List< Address > *, EventHandler * );
};


#endif
