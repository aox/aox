// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "messagecache.h"

#include "message.h"
#include "mailbox.h"
#include "server.h"
#include "map.h"

#include <time.h> // time(0)


static class MessageCache * c = 0;


class MessageCacheData
    : public Garbage
{
public:
    MessageCacheData(): Garbage() {}
    Map<Map<Message> > m;
};


/*! \class MessageCache messagecache.h

  The MessageCache class caches messages until the Allocator decides
  to clear out old Garbage. As a special feature, it can also cache
  messages a few seconds longer, although that should be used
  sparingly.
*/


/*! Constructs an empty MessageCache. Should not be called directly,
    only via insert() and find().
*/

MessageCache::MessageCache()
    : Cache(), d( new MessageCacheData )
{
    // nothing
}


/*! Inserts \a m into the cache, such that a find( \a mb, \a uid )
    will find it.
*/

void MessageCache::insert( class Mailbox * mb, uint uid,
                           class Message * m )
{
    if ( !Server::useCache() )
        return;
    if ( !c )
        c = new MessageCache;
    Map<Message> * mbcache = c->d->m.find( mb->id() );
    if ( !mbcache ) {
        mbcache = new Map<Message>;
        c->d->m.insert( mb->id(), mbcache );
    }
    mbcache->insert( uid, m );
}


/*! Looks for a message in \a mailbox with \a uid in the cache and
    returns a pointer to it, or a null pointer.
*/

class Message * MessageCache::find( class Mailbox * mailbox, uint uid )
{
    if ( !c )
        return 0;
    Map<Message> * mbcache = c->d->m.find( mailbox->id() );
    if ( mbcache )
        return mbcache->find( uid );
    return 0;
}


void MessageCache::clear()
{
    d->m.clear();
}
