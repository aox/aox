// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "status.h"

#include "map.h"
#include "flag.h"
#include "imap.h"
#include "cache.h"
#include "query.h"
#include "mailbox.h"
#include "imapsession.h"
#include "mailboxgroup.h"


class StatusData
    : public Garbage
{
public:
    StatusData() :
        messages( false ), uidnext( false ), uidvalidity( false ),
        recent( false ), unseen( false ),
        modseq( false ),
        mailbox( 0 ),
        unseenCount( 0 ), messageCount( 0 ), recentCount( 0 ),
        cacheState( 0 )
        {}
    bool messages, uidnext, uidvalidity, recent, unseen, modseq;
    Mailbox * mailbox;
    Query * unseenCount;
    Query * messageCount;
    Query * recentCount;
    uint cacheState;

    class CacheItem
        : public Garbage
    {
    public:
        CacheItem():
            hasMessages( false ), hasUnseen( false ), hasRecent( false ),
            messages( 0 ), unseen( 0 ), recent( 0 ),
            nextmodseq( 0 ), mailbox( 0 )
            {}
        bool hasMessages;
        bool hasUnseen;
        bool hasRecent;
        uint messages;
        uint unseen;
        uint recent;
        int64 nextmodseq;
        Mailbox * mailbox;
    };

    class StatusCache
        : public Cache
    {
    public:
        StatusCache(): Cache( 10 ) {}
        void clear() { c.clear(); }

        CacheItem * provide( Mailbox * m ) {
            CacheItem * i = 0;
            if ( !m )
                return i;
            i = c.find( m->id() );
            if ( !i ) {
                i = new CacheItem;
                i->mailbox = m;
                i->nextmodseq = m->nextModSeq();
                c.insert( m->id(), i );
            }
            if ( i->nextmodseq < m->nextModSeq() ) {
                i->nextmodseq = m->nextModSeq();
                i->hasMessages = false;
                i->hasUnseen = false;
                i->hasRecent = false;
            }
            return i;
        }
        CacheItem * find( uint id ) {
            return c.find( id );
        }

        Map<CacheItem> c;
    };
};


static StatusData::StatusCache * cache = 0;


/*! \class Status status.h
    Returns the status of the specified mailbox (RFC 3501 section 6.3.10)
*/

Status::Status()
    : d( new StatusData )
{
    setGroup( 4 );
}


void Status::parse()
{
    space();
    d->mailbox = mailbox();
    space();
    require( "(" );

    EString l( "Status " );
    if ( d->mailbox ) {
        l.append(  d->mailbox->name().ascii() );
        l.append( ":" );
    }
    bool atEnd = false;
    while ( !atEnd ) {
        EString item = letters( 1, 13 ).lower();
        l.append( " " );
        l.append( item );

        if ( item == "messages" )
            d->messages = true;
        else if ( item == "recent" )
            d->recent = true;
        else if ( item == "uidnext" )
            d->uidnext = true;
        else if ( item == "uidvalidity" )
            d->uidvalidity = true;
        else if ( item == "unseen" )
            d->unseen = true;
        else if ( item == "highestmodseq" )
            d->modseq = true;
        else
            error( Bad, "Unknown STATUS item: " + item );

        if ( nextChar() == ' ' )
            space();
        else
            atEnd = true;
    }

    require( ")" );
    end();
    if ( !ok() )
        return;

    log( l );
    requireRight( d->mailbox, Permissions::Read );
}


void Status::execute()
{
    if ( state() != Executing )
        return;

    // first part. set up.
    if ( !permitted() )
        return;

    Session * session = imap()->session();
    Mailbox * current = 0;
    if ( session )
        current = session->mailbox();

    // second part. see if anything has happened, and feed the cache if
    // so. make sure we feed the cache at once.
    if ( d->unseenCount || d->recentCount || d->messageCount ) {
        if ( d->unseenCount && !d->unseenCount->done() )
            return;
        if ( d->messageCount && !d->messageCount->done() )
            return;
        if ( d->recentCount && !d->recentCount->done() )
            return;
    }
    if ( !::cache )
        ::cache = new StatusData::StatusCache;
    
    if ( d->unseenCount ) {
        while ( d->unseenCount->hasResults() ) {
            Row * r = d->unseenCount->nextRow();
            StatusData::CacheItem * ci =
                ::cache->find( r->getInt( "mailbox" ) );
            if ( ci ) {
                ci->hasUnseen = true;
                ci->unseen = r->getInt( "unseen" );
            }
        }
    }
    if ( d->recentCount ) {
        while ( d->recentCount->hasResults() ) {
            Row * r = d->recentCount->nextRow();
            StatusData::CacheItem * ci =
                ::cache->find( r->getInt( "mailbox" ) );
            if ( ci ) {
                ci->hasRecent = true;
                ci->recent = r->getInt( "recent" );
            }
        }
    }
    if ( d->messageCount ) {
        while ( d->messageCount->hasResults() ) {
            Row * r = d->messageCount->nextRow();
            StatusData::CacheItem * ci =
                ::cache->find( r->getInt( "mailbox" ) );
            if ( ci ) {
                ci->hasMessages = true;
                ci->messages = r->getInt( "messages" );
            }
        }
    }

    // third part. are we processing the first command in a STATUS
    // loop? if so, see if we ought to preload the cache.
    if ( mailboxGroup() && d->cacheState < 3 ) {
        IntegerSet mailboxes;
        if ( d->cacheState < 1 ) {
            // cache state 0: decide which messages
            List<Mailbox>::Iterator i( mailboxGroup()->contents() );
            while ( i ) {
                StatusData::CacheItem * ci = ::cache->provide( i );
                bool need = false;
                if ( d->unseen || d->recent || d->messages )
                    need = true;
                if ( ci->hasUnseen || ci->hasRecent || ci->hasMessages )
                    need = false;
                if ( need )
                    mailboxes.add( i->id() );
                ++i;
            }
            if ( mailboxes.count() < 3 )
                d->cacheState = 3;
        }
        if ( d->cacheState == 1 ) {
            // state 1: send queries
            if ( d->unseen ) {
                d->unseenCount
                    = new Query( "select mailbox, count(uid)::int as unseen "
                                 "from mailbox_messages "
                                 "where mailbox=any($1) and not seen "
                                 "group by mailbox", this );
                d->unseenCount->bind( 1, mailboxes );
                d->unseenCount->execute();
            }
            if ( d->recent ) {
                d->recentCount
                    = new Query( "select id as mailbox, "
                                 "uidnext-first_recent as recent "
                                 "from mailboxes where id=any($1)", this );
                d->recentCount->bind( 1, mailboxes );
                d->recentCount->execute();
            }
            if ( d->messages ) {
                d->messageCount
                    = new Query( "select count(*)::int as messages, mailbox "
                                 "from mailbox_messages where mailbox=any($1) "
                                 "group by mailbox", this );
                d->messageCount->bind( 1, mailboxes );
                d->messageCount->execute();
            }
            d->cacheState = 2;
        }
        if ( d->cacheState == 2 ) {
            // state 2: mark the cache as complete.
            IntegerSet mailboxes;
            List<Mailbox>::Iterator i( mailboxGroup()->contents() );
            while ( i ) {
                StatusData::CacheItem * ci = ::cache->find( i->id() );
                if ( ci && d->unseenCount )
                    ci->hasUnseen = true;
                if ( ci && d->recentCount )
                    ci->hasRecent = true;
                if ( ci && d->messageCount )
                    ci->hasMessages = true;
                ++i;
            }
            // and drop the queries
            d->cacheState = 3;
            d->unseenCount = 0;
            d->recentCount = 0;
            d->messageCount = 0;
        }
    }

    // the cache item we'll actually read from
    StatusData::CacheItem * i = ::cache->provide( d->mailbox );

    // fourth part: send individual queries if there's anything we need
    if ( d->unseen && !d->unseenCount && !i->hasUnseen ) {
        d->unseenCount
            = new Query( "select $1::int as mailbox, "
                         "count(uid)::int as unseen "
                         "from mailbox_messages "
                         "where mailbox=$1 and not seen", this );
        d->unseenCount->bind( 1, d->mailbox->id() );
        d->unseenCount->execute();
    }

    if ( !d->recent ) {
        // nothing doing
    }
    else if ( d->mailbox == current ) {
        // we'll pick it up from the session
    }
    else if ( i->hasRecent ) {
        // the cache has it
    }
    else if ( !d->recentCount ) {
        d->recentCount
            = new Query( "select id as mailbox, "
                         "uidnext-first_recent as recent "
                         "from mailboxes where id=$1", this );
        d->recentCount->bind( 1, d->mailbox->id() );
        d->recentCount->execute();
    }

    if ( !d->messages ) {
        // we don't need to collect
    }
    else if ( d->mailbox == current ) {
        // we'll pick it up
    }
    else if ( i->hasMessages ) {
        // the cache has it
    }
    else if ( d->messages && !d->messageCount ) {
        d->messageCount
            = new Query( "select count(*)::int as messages, "
                         "$1::int as mailbox "
                         "from mailbox_messages where mailbox=$1", this );
        d->messageCount->bind( 1, d->mailbox->id() );
        d->messageCount->execute();
    }

    if ( d->unseenCount || d->recentCount || d->messageCount ) {
        if ( d->unseenCount && !d->unseenCount->done() )
            return;
        if ( d->messageCount && !d->messageCount->done() )
            return;
        if ( d->recentCount && !d->recentCount->done() )
            return;
    }

    // fifth part: return the payload.
    EStringList status;

    if ( d->messages && i->hasMessages )
        status.append( "MESSAGES " + fn( i->messages ) );
    else if ( d->messages && d->mailbox == current )
        status.append( "MESSAGES " + fn( session->messages().count() ) );

    if ( d->recent && i->hasRecent )
        status.append( "RECENT " + fn( i->recent ) );
    else if ( d->recent && d->mailbox == current )
        status.append( "RECENT " + fn( session->recent().count() ) );

    if ( d->uidnext )
        status.append( "UIDNEXT " + fn( d->mailbox->uidnext() ) );

    if ( d->uidvalidity )
        status.append( "UIDVALIDITY " + fn( d->mailbox->uidvalidity() ) );

    if ( d->unseen && i->hasUnseen )
        status.append( "UNSEEN " + fn( i->unseen ) );

    if ( d->modseq ) {
        int64 hms = d->mailbox->nextModSeq();
        // don't like this. an empty mailbox will have a STATUS HMS of
        // 1 before it receives its first message, and also 1 after.
        if ( hms > 1 )
            hms--;
        status.append( "HIGHESTMODSEQ " + fn( hms ) );
    }

    respond( "STATUS " + imapQuoted( d->mailbox ) +
             " (" + status.join( " " ) + ")" );
    finish();
}
