// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "mailboxchanges.h"

#include "json.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "integerset.h"
#include "allocator.h"
#include "estringlist.h"


class MailboxChangesData
    : public Garbage
{
public:
    MailboxChangesData()
        : find( 0 ), state( 0 ), since( 0 ), newState( 0 ),
          maxChanges( 256 ), first( new Map<int64> ),
          created( new IntegerSet ), destroyed( new IntegerSet ),
          more( false )
    {}

    Query * find;
    Query * state;
    int64 since;
    int64 newState;
    uint maxChanges;
    IntegerSet known;
    IntegerSet candidates;
    IntegerSet included;
    Map<int64> * first;
    IntegerSet * created;
    IntegerSet * destroyed;
    bool more;
};


/*! \class MailboxChanges mailboxchanges.h

    The MailboxChanges class implements Mailbox/changes of RFC8621 2.2.

    A mailbox changes when mail arrives or leaves, when its flags
    change, and when it is created, renamed or deleted. All of those
    now advance mailboxes.nextmodseq, and mailboxes.imodseq records
    when the mailbox was created, so the three lists this returns are
    the same question Email/changes answers, asked of mailboxes.

    Renaming reports the mailbox as updated rather than destroyed and
    created, which is right: the id does not change, and a client that
    knows the id learns the new name from Mailbox/get.
*/


/*! Constructs a Mailbox/changes for \a user with \a arguments,
    notifying \a owner when it has an answer.
*/

MailboxChanges::MailboxChanges( EventHandler * owner, User * user,
                                Json * arguments )
    : JmapMethod( owner, user, arguments ), d( new MailboxChangesData )
{
}


/*! Records \a m and its descendants, deleted ones included, as
    mailboxes this account may have to report on.
*/

void MailboxChanges::collect( Mailbox * m )
{
    if ( !m )
        return;
    if ( m->id() && !m->isHome() )
        d->known.add( m->id() );
    List<Mailbox> * c = m->children();
    if ( !c )
        return;
    List<Mailbox>::Iterator i( c );
    while ( i ) {
        collect( i );
        ++i;
    }
}


void MailboxChanges::execute()
{
    if ( !d->find ) {
        if ( !checkAccount() )
            return;

        Json * s = arguments()->member( "sinceState" );
        if ( !s || !s->valid( Json::String ) ) {
            fail( "invalidArguments" );
            return;
        }
        EString since = s->ascii();
        bool ok = false;
        if ( since.startsWith( "m" ) )
            d->since = since.mid( 1 ).number( &ok );
        if ( !ok ) {
            fail( "cannotCalculateChanges" );
            return;
        }

        Json * m = arguments()->member( "maxChanges" );
        if ( m ) {
            if ( !m->valid( Json::Number ) || m->number() <= 0 ) {
                fail( "invalidArguments" );
                return;
            }
            if ( (uint)m->number() < d->maxChanges )
                d->maxChanges = (uint)m->number();
        }

        // Deleted mailboxes lose their owner, so the account's
        // mailboxes are found in the tree rather than by owner.
        collect( Mailbox::find( user()->home()->name() ) );
        if ( d->known.isEmpty() ) {
            d->known.add( 0 );
        }

        d->find = new Query( "select id, imodseq, nextmodseq, deleted "
                             "from mailboxes where id=any($1) "
                             "and nextmodseq>$2", this );
        d->find->bind( 1, d->known );
        d->find->bind( 2, (int64)d->since + 1 );
        d->find->execute();

        d->state = new Query( "select last_value from nextmodseq", this );
        d->state->execute();
    }

    if ( !d->find->done() || !d->state->done() )
        return;
    if ( d->find->failed() ) {
        fail( "serverFail" );
        return;
    }

    Row * r;
    while ( (r=d->find->nextRow()) != 0 ) {
        uint id = r->getInt( "id" );
        int64 imodseq = r->getBigint( "imodseq" );
        int64 nextmodseq = r->getBigint( "nextmodseq" );
        d->candidates.add( id );
        // The mailbox changed somewhere between the state the client
        // holds and its nextmodseq; the latter is the best marker we
        // have of when, and the only one that matters for ordering.
        int64 * f = (int64*)Allocator::alloc( sizeof( int64 ), 0 );
        *f = nextmodseq - 1;
        d->first->insert( id, f );
        if ( r->getBoolean( "deleted" ) )
            d->destroyed->add( id );
        else if ( imodseq > d->since )
            d->created->add( id );
    }

    d->newState = 1;
    r = d->state->nextRow();
    if ( r )
        d->newState = r->getBigint( "last_value" );
    if ( d->since > d->newState ) {
        fail( "cannotCalculateChanges" );
        return;
    }

    if ( d->candidates.count() > d->maxChanges )
        d->newState = splitChanges( d->candidates, *d->first, d->maxChanges,
                                    d->included, d->more );
    else
        d->included = d->candidates;

    Json * created = Json::list();
    Json * updated = Json::list();
    Json * destroyed = Json::list();
    uint n = 1;
    while ( n <= d->included.count() ) {
        uint id = d->included.value( n );
        n++;
        Json * i = Json::string( "f" + fn( id ) );
        if ( d->destroyed->contains( id ) )
            destroyed->append( i );
        else if ( d->created->contains( id ) )
            created->append( i );
        else
            updated->append( i );
    }

    Json * response = Json::object();
    response->insert( "accountId", Json::string( fn( user()->id() ) ) );
    response->insert( "oldState", Json::string( "m" + fn( d->since ) ) );
    response->insert( "newState", Json::string( "m" + fn( d->newState ) ) );
    response->insert( "hasMoreChanges", Json::boolean( d->more ) );
    response->insert( "created", created );
    response->insert( "updated", updated );
    response->insert( "destroyed", destroyed );
    respond( "Mailbox/changes", response );
}
