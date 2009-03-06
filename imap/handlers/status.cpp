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
        checkedGroup( false ), group( 0 )
        {}
    bool messages, uidnext, uidvalidity, recent, unseen, modseq;
    Mailbox * mailbox;
    Query * unseenCount;
    Query * messageCount;
    Query * recentCount;
    bool checkedGroup;
    MailboxGroup * group;

    class CacheItem
        : public Garbage
    {
    public:
        CacheItem():
            hasMessages( false ), hasUnseen( false ), hasRecent( false ),
            messages( 0 ), unseen( 0 ), recent( 0 ),
            nextmodseq( 0 )
            {}
        bool hasMessages;
        bool hasUnseen;
        bool hasRecent;
        uint messages;
        uint unseen;
        uint recent;
        int64 nextmodseq;
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

    Session * session = imap()->session();
    Mailbox * current = 0;
    if ( session )
        current = session->mailbox();

    if ( !d->checkedGroup ) {
        d->group = imap()->mostLikelyGroup( d->mailbox, 3 );
        d->checkedGroup = true;
    }

    if ( !::cache )
        ::cache = new StatusData::StatusCache;
    StatusData::CacheItem * i = ::cache->provide( d->mailbox );

    IntegerSet mailboxes;
    if ( d->group ) {
        mailboxes.add( d->mailbox->id() );
        List<Mailbox>::Iterator i( d->group->contents() );
        while ( i ) {
            mailboxes.add( i->id() );
            ++i;
        }
    }

    if ( d->unseen && !d->unseenCount && !i->hasUnseen ) {
        // UNSEEN is horribly slow. I don't think this is fixable
        // really.
        d->unseenCount
            = new Query( "select "
                         "(select count(*)::int from mailbox_messages"
                         " where mailbox=$1)-"
                         "(select count(*)::int from flags"
                         " where mailbox=$1 and flag=$2) "
                         "as unseen, $1 as mailbox", this );
        d->unseenCount->bind( 1, d->mailbox->id() );

        uint sid = Flag::id( "\\seen" );
        if ( sid ) {
            d->unseenCount->bind( 2, sid );
            d->unseenCount->execute();
        }
        else {
            // what can we do? at least not crash.
            d->unseen = false;
            d->unseenCount = false;
        }
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
        if ( d->group ) {
            d->recentCount
                = new Query( "select mailbox, uidnext-first_recent as recent "
                             "from mailboxes "
                             "where id=any($1)", this );
            d->recentCount->bind( 1, mailboxes );
        }
        else {
            d->recentCount
                = new Query( "select mailbox, uidnext-first_recent as recent "
                             "from mailboxes "
                             "where id=$1", this );
            d->recentCount->bind( 1, d->mailbox->id() );
        }
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
        if ( d->group ) {
            d->messageCount
                = new Query( "select count(*)::int as messages, mailbox "
                             "from mailbox_messages where mailbox=any($1) "
                             "group by mailbox", this );
            d->messageCount->bind( 1, mailboxes );
        }
        else {
            d->messageCount
                = new Query( "select count(*)::int as messages, $1 as mailbox "
                             "from mailbox_messages where mailbox=$1", this );
            d->messageCount->bind( 1, d->mailbox->id() );
        }
        d->messageCount->execute();
    }

    // second part: wait until we have the information
    if ( !permitted() )
        return;
    if ( d->unseenCount && !d->unseenCount->done() )
        return;
    if ( d->messageCount && !d->messageCount->done() )
        return;
    if ( d->recentCount && !d->recentCount->done() )
        return;

    if ( d->group ) {
        // the queries often return zero rows if all the numbers are
        // zero, so we have to fill in hasRecent etc. even if we don't
        // get a row.
        List<Mailbox> * l = d->group->contents();
        l->append( d->mailbox );
        List<Mailbox>::Iterator i( l );
        while ( i ) {
            StatusData::CacheItem * ci = ::cache->provide( i );
            if ( d->messageCount )
                ci->hasMessages = true;
            if ( d->recentCount )
                ci->hasMessages = true;
            // but we cannot set hasUnseen here, since the query above
            // doesn't do the real thing.
            ++i;
        }
    }

    // third part: return the payload.
    EStringList status;

    if ( d->messageCount ) {
        while ( d->messageCount->hasResults() ) {
            Row * r = d->messageCount->nextRow();
            Mailbox * m = Mailbox::find( r->getInt( "mailbox" ) );
            StatusData::CacheItem * ci = ::cache->provide( m );
            if ( ci )
                ci->messages = r->getInt( "messages" );
        }
    }
    if ( d->messages && i->hasMessages )
        status.append( "MESSAGES " + fn( i->messages ) );
    else if ( d->messages && d->mailbox == current )
        status.append( "MESSAGES " + fn( session->messages().count() ) );

    if ( d->recentCount ) {
        while ( d->recentCount->hasResults() ) {
            Row * r = d->recentCount->nextRow();
            Mailbox * m = Mailbox::find( r->getInt( "mailbox" ) );
            StatusData::CacheItem * ci = ::cache->provide( m );
            if ( ci )
                ci->recent = r->getInt( "recent" );
        }
    }
    if ( d->recent && i->hasRecent )
        status.append( "RECENT " + fn( i->recent ) );
    else if ( d->recent && d->mailbox == current )
        status.append( "RECENT " + fn( session->recent().count() ) );

    if ( d->uidnext )
        status.append( "UIDNEXT " + fn( d->mailbox->uidnext() ) );

    if ( d->uidvalidity )
        status.append( "UIDVALIDITY " + fn( d->mailbox->uidvalidity() ) );

    if ( d->unseenCount ) {
        while ( d->unseenCount->hasResults() ) {
            Row * r = d->unseenCount->nextRow();
            Mailbox * m = Mailbox::find( r->getInt( "mailbox" ) );
            StatusData::CacheItem * ci = ::cache->provide( m );
            if ( ci ) {
                ci->hasUnseen = true;
                ci->unseen = r->getInt( "unseen" );
            }
        }
    }
    if ( d->unseen && i->hasUnseen )
        status.append( "UNSEEN " + fn( i->unseen ) );

    if ( d->modseq )
        status.append( "HIGHESTMODSEQ " + fn( d->mailbox->nextModSeq() - 1 ) );

    respond( "STATUS " + imapQuoted( d->mailbox ) +
             " (" + status.join( " " ) + ")" );
    finish();
}
