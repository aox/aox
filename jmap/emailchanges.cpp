// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "emailchanges.h"

#include "map.h"
#include "allocator.h"
#include "json.h"
#include "user.h"
#include "query.h"
#include "selector.h"
#include "integerset.h"
#include "estringlist.h"


class EmailChangesData
    : public Garbage
{
public:
    EmailChangesData()
        : existing( 0 ), gone( 0 ), state( 0 ), current( 0 ),
          since( 0 ), newState( 0 ), maxChanges( 256 ),
          first( new Map<int64> ), more( false )
    {}

    Query * existing;
    Query * gone;
    Query * state;
    Query * current;
    int64 since;
    int64 newState;
    uint maxChanges;
    IntegerSet candidates;
    IntegerSet included;
    Map<int64> * first;
    bool more;
};


/*! \class EmailChanges emailchanges.h

    The EmailChanges class implements Email/changes of RFC8621 4.3, which
    makes a read-only API usable for more than singel use: without it an
    agent that wants to know whether a message became $seen has to read
    the mailbox again, which is the thing this API exists to avoid.
*/


/*! Constructs an Email/changes for \a user with \a arguments, notifying
    \a owner when it has an answer.
*/

EmailChanges::EmailChanges( EventHandler * owner, User * user,
                            Json * arguments )
    : JmapMethod( owner, user, arguments ), d( new EmailChangesData )
{
}


void EmailChanges::execute()
{
    if ( !d->existing ) {
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
            // Not a state this server ever issued, so we cannot say
            // what has changed since it.
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

        // Larger means >=, so this asks for changes after the state.
        EStringList wanted;
        wanted.append( "message" );
        wanted.append( "modseq" );

        Selector * e = new Selector( Selector::Modseq, Selector::Larger,
                                     (uint)d->since + 1 );
        e->simplify();
        d->existing = e->query( user(), 0, 0, this, false, &wanted, false );
        d->existing->execute();

        // The same question of deleted_messages: a message that left
        // the account is a destruction, and one that left a single
        // mailbox is a change to mailboxIds.
        Selector * g = new Selector( Selector::Modseq, Selector::Larger,
                                     (uint)d->since + 1 );
        g->simplify();
        d->gone = g->query( user(), 0, 0, this, false, &wanted, true );
        d->gone->execute();

        d->state = new Query( "select last_value from nextmodseq", this );
        d->state->execute();
    }

    if ( !d->existing->done() || !d->gone->done() || !d->state->done() )
        return;

    if ( d->existing->failed() || d->gone->failed() ) {
        fail( "serverFail" );
        return;
    }

    if ( !d->current ) {
        Row * r;
        while ( (r=d->existing->nextRow()) != 0 ) {
            uint message = r->getInt( "message" );
            int64 modseq = r->getBigint( "modseq" );
            int64 * f = d->first->find( message );
            if ( !f ) {
                f = (int64*)Allocator::alloc( sizeof( int64 ), 0 );
                *f = modseq;
                d->first->insert( message, f );
                d->candidates.add( message );
            }
            else if ( modseq < *f ) {
                *f = modseq;
            }
        }
        while ( (r=d->gone->nextRow()) != 0 ) {
            uint message = r->getInt( "message" );
            int64 modseq = r->getBigint( "modseq" );
            int64 * f = d->first->find( message );
            if ( !f ) {
                f = (int64*)Allocator::alloc( sizeof( int64 ), 0 );
                *f = modseq;
                d->first->insert( message, f );
                d->candidates.add( message );
            }
            else if ( modseq < *f ) {
                *f = modseq;
            }
        }

        d->newState = 1;
        r = d->state->nextRow();
        if ( r )
            d->newState = r->getBigint( "last_value" );
        if ( d->since > d->newState ) {
            // A state from the future: not one we issued.
            fail( "cannotCalculateChanges" );
            return;
        }

        // maxChanges counts changes, and the client must be able to
        // continue from the state we return, so changes that share a
        // modseq are never split: we add whole groups, in modseq
        // order, while they fit. A single group larger than maxChanges
        // is returned whole, because the alternative is to return
        // nothing and never make progress.
        if ( d->candidates.count() > d->maxChanges ) {
            int64 boundary = 0;
            uint taken = 0;
            bool more = true;
            while ( more ) {
                int64 next = 0;
                uint group = 0;
                uint n = 1;
                while ( n <= d->candidates.count() ) {
                    int64 m = *d->first->find( d->candidates.value( n ) );
                    if ( m > boundary && ( !next || m < next ) ) {
                        next = m;
                        group = 0;
                    }
                    if ( next && m == next )
                        group++;
                    n++;
                }
                if ( !next )
                    more = false;
                else if ( taken && taken + group > d->maxChanges )
                    more = false;
                else {
                    boundary = next;
                    taken += group;
                }
            }
            uint n = 1;
            while ( n <= d->candidates.count() ) {
                uint message = d->candidates.value( n );
                if ( *d->first->find( message ) <= boundary )
                    d->included.add( message );
                else
                    d->more = true;
                n++;
            }
            d->newState = boundary;
        }
        else {
            d->included = d->candidates;
        }

        if ( d->included.isEmpty() ) {
            Json * r = Json::object();
            r->insert( "accountId", Json::string( fn( user()->id() ) ) );
            r->insert( "oldState", Json::string( "m" + fn( d->since ) ) );
            r->insert( "newState", Json::string( "m" + fn( d->newState ) ) );
            r->insert( "hasMoreChanges", Json::boolean( false ) );
            r->insert( "created", Json::list() );
            r->insert( "updated", Json::list() );
            r->insert( "destroyed", Json::list() );
            respond( "Email/changes", r );
            return;
        }

        // Which of these messages the account still holds, and when
        // each arrived. A message the account no longer holds anywhere
        // was destroyed; one that arrived after the client's state is
        // created; the rest are updated.
        Selector * s = new Selector( Selector::Or );
        uint n = 1;
        while ( n <= d->included.count() ) {
            s->add( new Selector( Selector::DatabaseId, Selector::Equals,
                                  d->included.value( n ) ) );
            n++;
        }
        s->simplify();
        EStringList wanted;
        wanted.append( "message" );
        wanted.append( "m.imodseq" );
        d->current = s->query( user(), 0, 0, this, false, &wanted, false );
        d->current->execute();
    }

    if ( !d->current->done() )
        return;
    if ( d->current->failed() ) {
        fail( "serverFail" );
        return;
    }

    Map<int64> arrived;
    Row * r;
    while ( (r=d->current->nextRow()) != 0 ) {
        uint message = r->getInt( "message" );
        int64 imodseq = r->getBigint( "imodseq" );
        if ( !arrived.find( message ) ) {
            int64 * a = (int64*)Allocator::alloc( sizeof( int64 ), 0 );
            *a = imodseq;
            arrived.insert( message, a );
        }
    }

    Json * created = Json::list();
    Json * updated = Json::list();
    Json * destroyed = Json::list();
    uint n = 1;
    while ( n <= d->included.count() ) {
        uint message = d->included.value( n );
        n++;
        Json * id = Json::string( "m" + fn( message ) );
        int64 * a = arrived.find( message );
        if ( !a )
            destroyed->append( id );
        else if ( *a > d->since )
            created->append( id );
        else
            updated->append( id );
    }

    Json * response = Json::object();
    response->insert( "accountId", Json::string( fn( user()->id() ) ) );
    response->insert( "oldState", Json::string( "m" + fn( d->since ) ) );
    response->insert( "newState", Json::string( "m" + fn( d->newState ) ) );
    response->insert( "hasMoreChanges", Json::boolean( d->more ) );
    response->insert( "created", created );
    response->insert( "updated", updated );
    response->insert( "destroyed", destroyed );
    respond( "Email/changes", response );
}
