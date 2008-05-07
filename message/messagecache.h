// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MESSAGECACHE_H
#define MESSAGECACHE_H

#include "cache.h"


class MessageCache
    : public Cache
{
private:
    MessageCache();

public:
    static void insert( class Mailbox *, uint, class Message *, uint = 0 );
    static class Message * find( class Mailbox *, uint );
    
    void clear();

private:
    class MessageCacheData * d;
};


#endif
