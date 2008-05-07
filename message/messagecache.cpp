// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "messagecache.h"

#include "message.h"
#include "mailbox.h"
#include "dict.h"
#include "list.h"

#include <time.h> // time(0)


static class MessageCache * c = 0;


class MessageCacheData
    : public Garbage
{
public:
    MessageCacheData()
        : m( 0 ) {}
    Dict<Message> * m;

    struct ValuableMessage
        : public Garbage
    {
    public:
        ValuableMessage() 
            : Garbage(),
              message( 0 ), ttl( 0 ), mailbox( 0 ), uid( 0 ) {}
        Message * message;
        uint ttl;
        Mailbox * mailbox;
        uint uid;
    };

    List<ValuableMessage> v;
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
    will find it. If \a ttl is supplied and nonzero (the default is
    zero), then \a m will be kept in RAM for at least \a ttl seconds.
*/

void MessageCache::insert( class Mailbox * mb, uint uid, 
                           class Message * m, uint ttl )
{
    if ( !c )
        c = new MessageCache;
    if ( !c->d->m )
        c->d->m = new Dict<Message>( 1024 );
    String hack;
    hack.append( mb->id() ); // <- that is a unicode codepoint, ahem
    hack.append( uid ); // <- that is also a unicode codepoint, ahem ahem
    c->d->m->insert( hack, m );
    if ( !ttl )
        return;
    MessageCacheData::ValuableMessage * v 
        = new MessageCacheData::ValuableMessage;
    v->ttl = (uint)time( 0 ) + ttl;
    v->message = m;
    v->mailbox = mb;
    v->uid = uid;
    c->d->v.append( v );
}


/*! Looks for a message in \a mailbox with \a uid in the cache and
    returns a pointer to it, or a null pointer.
*/

class Message * MessageCache::find( class Mailbox * mailbox, uint uid )
{
    if ( !c || !c->d->m )
        return 0;
    String hack;
    hack.append( mailbox->id() );
    hack.append( uid );
    return c->d->m->find( hack );
}


void MessageCache::clear()
{
    d->m = 0;
    if ( d->v.isEmpty() )
        return;
    uint now = (uint)time( 0 );
    List<MessageCacheData::ValuableMessage>::Iterator i( d->v );
    while ( i ) {
        List<MessageCacheData::ValuableMessage>::Iterator v( i );
        ++i;
        if ( v->ttl >= now ) {
            if ( !d->m )
                d->m = new Dict<Message>( 1024 );
            String hack;
            hack.append( v->mailbox->id() );
            hack.append( v->uid );
            d->m->insert( hack, v->message );
        }
        else {
            d->v.take( v );
        }
    }
}
