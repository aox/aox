// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "mailboxget.h"

#include "map.h"
#include "json.h"
#include "user.h"
#include "flag.h"
#include "query.h"
#include "mailbox.h"
#include "estringlist.h"


class MailboxGetData
    : public Garbage
{
public:
    MailboxGetData()
        : counts( 0 ), subscriptions( 0 ), state( 0 ),
          mailboxes( new List<Mailbox> ),
          subscribed( new IntegerSet ),
          total( new Map<uint> ), unread( new Map<uint> ),
          threads( new Map<uint> ), unreadThreads( new Map<uint> ),
          wantCounts( false ), wantSubscribed( false )
    {}

    Query * counts;
    Query * subscriptions;
    Query * state;
    List<Mailbox> * mailboxes;
    IntegerSet * subscribed;
    Map<uint> * total;
    Map<uint> * unread;
    Map<uint> * threads;
    Map<uint> * unreadThreads;
    EStringList properties;
    IntegerSet wanted;
    IntegerSet notFound;
    bool wantCounts;
    bool wantSubscribed;
};


/*! \class MailboxGet mailboxget.h

    The MailboxGet class implements Mailbox/get of RFC8621 2.1. The
    ids are the ids IMAP's OBJECTID extension reports as MAILBOXID, so
    a client that saw f2472 over IMAP asks for f2472 here.

    This lists the mailboxes the user owns, and not any shared mailboxes.

    The rights reported are what this API can do, not what the account
    could do over IMAP: every write right is false, because the session
    is read-only. A client that wants to know whether the user could in
    principle file a message has asked the wrong server.
*/


static const char * defaultProperties[] = {
    "id", "name", "parentId", "role", "sortOrder", "totalEmails",
    "unreadEmails", "totalThreads", "unreadThreads", "myRights",
    "isSubscribed", 0
};


/*! Constructs a Mailbox/get for \a user with \a arguments, notifying
    \a owner when it has an answer.
*/

MailboxGet::MailboxGet( EventHandler * owner, User * user, Json * arguments )
    : JmapMethod( owner, user, arguments ), d( new MailboxGetData )
{
}


/*! Adds \a m and its descendants to the list this will describe. */

void MailboxGet::collect( Mailbox * m )
{
    if ( !m )
        return;
    if ( m->id() && !m->deleted() && !m->isHome() ) {
        if ( d->wanted.isEmpty() || d->wanted.contains( m->id() ) )
            d->mailboxes->append( m );
    }
    List<Mailbox> * c = m->children();
    if ( !c )
        return;
    List<Mailbox>::Iterator i( c );
    while ( i ) {
        collect( i );
        ++i;
    }
}


/*! Returns the JMAP Mailbox object for \a m. */

Json * MailboxGet::mailbox( Mailbox * m )
{
    Json * r = Json::object();
    EStringList::Iterator p( d->properties );
    while ( p ) {
        EString property = *p;
        ++p;

        if ( property == "id" ) {
            r->insert( "id", Json::string( "f" + fn( m->id() ) ) );
        }
        else if ( property == "name" ) {
            // JMAP names a mailbox by its own name, not by its path
            UString name = m->name();
            int slash = -1;
            uint i = 0;
            while ( i < name.length() ) {
                if ( name[i] == '/' )
                    slash = i;
                i++;
            }
            r->insert( "name", Json::string( name.mid( slash + 1 ) ) );
        }
        else if ( property == "parentId" ) {
            Mailbox * parent = m->parent();
            if ( parent && parent->id() && !parent->isHome() )
                r->insert( "parentId",
                           Json::string( "f" + fn( parent->id() ) ) );
            else
                r->insert( "parentId", new Json( Json::Null ) );
        }
        else if ( property == "role" ) {
            // JMAP spells the roles like RFC6154 without the backslash,
            // and has one RFC6154 does not: the inbox.
            if ( user()->inbox() == m )
                r->insert( "role", Json::string( EString( "inbox" ) ) );
            else if ( m->flag().isEmpty() )
                r->insert( "role", new Json( Json::Null ) );
            else
                r->insert( "role",
                           Json::string( m->flag().mid( 1 ).lower() ) );
        }
        else if ( property == "sortOrder" ) {
            r->insert( "sortOrder", Json::number( 0 ) );
        }
        else if ( property == "totalEmails" || property == "unreadEmails" ||
                  property == "totalThreads" ||
                  property == "unreadThreads" ) {
            Map<uint> * source = d->total;
            if ( property == "unreadEmails" )
                source = d->unread;
            else if ( property == "totalThreads" )
                source = d->threads;
            else if ( property == "unreadThreads" )
                source = d->unreadThreads;
            uint * n = source->find( m->id() );
            r->insert( property, Json::number( n ? *n : 0 ) );
        }
        else if ( property == "myRights" ) {
            Json * rights = Json::object();
            rights->insert( "mayReadItems", Json::boolean( true ) );
            rights->insert( "mayAddItems", Json::boolean( false ) );
            rights->insert( "mayRemoveItems", Json::boolean( false ) );
            rights->insert( "maySetSeen", Json::boolean( false ) );
            rights->insert( "maySetKeywords", Json::boolean( false ) );
            rights->insert( "mayCreateChild", Json::boolean( false ) );
            rights->insert( "mayRename", Json::boolean( false ) );
            rights->insert( "mayDelete", Json::boolean( false ) );
            rights->insert( "maySubmit", Json::boolean( false ) );
            r->insert( "myRights", rights );
        }
        else if ( property == "isSubscribed" ) {
            r->insert( "isSubscribed",
                       Json::boolean( d->subscribed->contains( m->id() ) ) );
        }
    }
    return r;
}


void MailboxGet::execute()
{
    if ( !d->state ) {
        if ( !checkAccount() )
            return;

        Json * ids = arguments()->member( "ids" );
        if ( ids && !ids->valid( Json::Null ) ) {
            if ( !ids->valid( Json::Array ) ) {
                fail( "invalidArguments" );
                return;
            }
            List<Json>::Iterator i( ids->array() );
            while ( i ) {
                if ( i->valid( Json::String ) ) {
                    EString id = i->ascii();
                    bool ok = false;
                    uint n = 0;
                    if ( id.startsWith( "f" ) )
                        n = id.mid( 1 ).number( &ok );
                    if ( ok && n )
                        d->wanted.add( n );
                    else
                        d->notFound.add( 0 );
                }
                ++i;
            }
        }

        Json * properties = arguments()->member( "properties" );
        if ( properties && properties->valid( Json::Array ) ) {
            List<Json>::Iterator p( properties->array() );
            while ( p ) {
                if ( !p->valid( Json::String ) ) {
                    fail( "invalidArguments" );
                    return;
                }
                d->properties.append( p->ascii() );
                ++p;
            }
            if ( !d->properties.contains( "id" ) )
                d->properties.append( "id" );
        }
        else {
            uint n = 0;
            while ( defaultProperties[n] ) {
                d->properties.append( defaultProperties[n] );
                n++;
            }
        }
        d->wantCounts = d->properties.contains( "totalEmails" ) ||
                        d->properties.contains( "unreadEmails" ) ||
                        d->properties.contains( "totalThreads" ) ||
                        d->properties.contains( "unreadThreads" );
        d->wantSubscribed = d->properties.contains( "isSubscribed" );

        collect( Mailbox::find( user()->home()->name() ) );

        IntegerSet ids2;
        List<Mailbox>::Iterator m( d->mailboxes );
        while ( m ) {
            ids2.add( m->id() );
            ++m;
        }

        if ( d->wantCounts && !ids2.isEmpty() ) {
            // One pass over the user's mail: the counts per mailbox,
            // with unread meaning "no \Seen flag of this user's".
            d->counts = new Query(
                "select mm.mailbox, count(*)::int as total, "
                "count(*) filter (where not exists "
                "(select 1 from flags f where f.message=mm.message "
                "and f.flag=$1 and f.owner=$2))::int as unread, "
                "count(distinct m.thread_root)::int as threads, "
                "count(distinct m.thread_root) filter (where not exists "
                "(select 1 from flags f where f.message=mm.message "
                "and f.flag=$1 and f.owner=$2))::int as unreadthreads "
                "from mailbox_messages mm "
                "join messages m on (m.id=mm.message) "
                "where mm.mailbox=any($3) "
                "group by mm.mailbox", this );
            d->counts->bind( 1, Flag::id( "\\seen" ) );
            d->counts->bind( 2, user()->id() );
            d->counts->bind( 3, ids2 );
            d->counts->execute();
        }

        if ( d->wantSubscribed && !ids2.isEmpty() ) {
            d->subscriptions = new Query( "select mailbox from subscriptions "
                                          "where owner=$1 "
                                          "and mailbox=any($2)", this );
            d->subscriptions->bind( 1, user()->id() );
            d->subscriptions->bind( 2, ids2 );
            d->subscriptions->execute();
        }

        d->state = new Query( "select last_value from nextmodseq", this );
        d->state->execute();
    }

    if ( d->counts && !d->counts->done() )
        return;
    if ( d->subscriptions && !d->subscriptions->done() )
        return;
    if ( !d->state->done() )
        return;

    Row * r;
    while ( d->counts && (r=d->counts->nextRow()) != 0 ) {
        uint mailbox = r->getInt( "mailbox" );
        uint * t = (uint*)Allocator::alloc( sizeof( uint ), 0 );
        *t = r->getInt( "total" );
        d->total->insert( mailbox, t );
        uint * u = (uint*)Allocator::alloc( sizeof( uint ), 0 );
        *u = r->getInt( "unread" );
        d->unread->insert( mailbox, u );
        uint * th = (uint*)Allocator::alloc( sizeof( uint ), 0 );
        *th = r->getInt( "threads" );
        d->threads->insert( mailbox, th );
        uint * ut = (uint*)Allocator::alloc( sizeof( uint ), 0 );
        *ut = r->getInt( "unreadthreads" );
        d->unreadThreads->insert( mailbox, ut );
    }
    while ( d->subscriptions && (r=d->subscriptions->nextRow()) != 0 )
        d->subscribed->add( r->getInt( "mailbox" ) );

    Json * list = Json::list();
    List<Mailbox>::Iterator m( d->mailboxes );
    while ( m ) {
        list->append( mailbox( m ) );
        ++m;
    }

    Json * notFound = Json::list();
    uint n = 1;
    while ( n <= d->wanted.count() ) {
        uint id = d->wanted.value( n );
        Mailbox * mb = Mailbox::find( id );
        bool found = false;
        List<Mailbox>::Iterator i( d->mailboxes );
        while ( i && !found ) {
            if ( i == mb )
                found = true;
            ++i;
        }
        if ( !found )
            notFound->append( Json::string( "f" + fn( id ) ) );
        n++;
    }

    int64 state = 1;
    r = d->state->nextRow();
    if ( r )
        state = r->getBigint( "last_value" );

    Json * response = Json::object();
    response->insert( "accountId", Json::string( fn( user()->id() ) ) );
    response->insert( "state", Json::string( "m" + fn( state ) ) );
    response->insert( "list", list );
    response->insert( "notFound", notFound );
    respond( "Mailbox/get", response );
}
