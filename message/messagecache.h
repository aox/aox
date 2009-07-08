// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MESSAGECACHE_H
#define MESSAGECACHE_H

#include "cache.h"


class MessageCache
    : public Cache
{
private:
    MessageCache();

public:
    static void insert( class Mailbox *, uint, class Message * );
    static class Message * find( class Mailbox *, uint );
    static class Message * provide( class Mailbox *, uint );

    void clear();

private:
    class MessageCacheData * d;
};


#endif
