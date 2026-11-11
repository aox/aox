// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "threadget.h"

#include "map.h"
#include "json.h"
#include "user.h"
#include "list.h"
#include "query.h"
#include "selector.h"
#include "estringlist.h"


class ThreadRow
    : public Garbage
{
public:
    ThreadRow(): thread( 0 ), message( 0 ), idate( 0 ) {}

    uint thread;
    uint message;
    uint idate;
};


class ThreadGetData
    : public Garbage
{
public:
    ThreadGetData()
        : find( 0 ), state( 0 ), threads( new Map< List<ThreadRow> > ),
          wantEmailIds( true )
    {}

    Query * find;
    Query * state;
    Map< List<ThreadRow> > * threads;
    IntegerSet ids;
    bool wantEmailIds;
};


/*! \class ThreadGet threadget.h

    The ThreadGet class implements Thread/get of RFC8621 3.2, with the
    same IDs as in IMAP OBJECTID.
*/


/*! Constructs a Thread/get for \a user with \a arguments, notifying
    \a owner when it has an answer.
*/

ThreadGet::ThreadGet( EventHandler * owner, User * user, Json * arguments )
    : JmapMethod( owner, user, arguments ), d( new ThreadGetData )
{
}


void ThreadGet::execute()
{
    if ( !d->find ) {
        if ( !checkAccount() )
            return;

        Json * ids = arguments()->member( "ids" );
        if ( !ids || !ids->valid( Json::Array ) ) {
            // ids:null means every thread in the account, which is
            // not a question we answer.
            fail( "requestTooLarge" );
            return;
        }
        if ( ids->array()->count() > 64 ) {
            fail( "requestTooLarge" );
            return;
        }
        List<Json>::Iterator i( ids->array() );
        while ( i ) {
            if ( i->valid( Json::String ) ) {
                EString id = i->ascii();
                if ( id.startsWith( "t" ) ) {
                    bool ok = false;
                    uint n = id.mid( 1 ).number( &ok );
                    if ( ok && n )
                        d->ids.add( n );
                }
            }
            ++i;
        }

        Json * properties = arguments()->member( "properties" );
        if ( properties && properties->valid( Json::Array ) ) {
            d->wantEmailIds = false;
            List<Json>::Iterator p( properties->array() );
            while ( p ) {
                if ( !p->valid( Json::String ) ) {
                    fail( "invalidArguments" );
                    return;
                }
                EString name = p->ascii();
                if ( name == "emailIds" )
                    d->wantEmailIds = true;
                else if ( name != "id" ) {
                    fail( "invalidArguments" );
                    return;
                }
                ++p;
            }
        }

        if ( d->ids.isEmpty() ) {
            Json * r = Json::object();
            r->insert( "accountId", Json::string( fn( user()->id() ) ) );
            r->insert( "state", Json::string( EString( "m0" ) ) );
            r->insert( "list", Json::list() );
            r->insert( "notFound", Json::list() );
            respond( "Thread/get", r );
            return;
        }

        // Selector decides what this user may see, just as in
        // Email/get, so a thread held entirely in someone else's
        // mailbox is notFound rather than readable.
        Selector * s = new Selector( Selector::Or );
        uint n = 1;
        while ( n <= d->ids.count() ) {
            s->add( new Selector( Selector::ThreadId, Selector::Equals,
                                  d->ids.value( n ) ) );
            n++;
        }
        s->simplify();
        EStringList wanted;
        wanted.append( "message" );
        wanted.append( "m.idate" );
        wanted.append( "m.thread_root" );
        d->find = s->query( user(), 0, 0, this, false, &wanted, false );
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
        ThreadRow * tr = new ThreadRow;
        tr->thread = r->getInt( "thread_root" );
        tr->message = r->getInt( "message" );
        tr->idate = r->getInt( "idate" );
        List<ThreadRow> * l = d->threads->find( tr->thread );
        if ( !l ) {
            l = new List<ThreadRow>;
            d->threads->insert( tr->thread, l );
        }
        // the same message can arrive once per mailbox it is in, and
        // the order is oldest first, ties broken by id so that a
        // client sees the same order twice running
        List<ThreadRow>::Iterator i( l );
        while ( i && ( i->idate < tr->idate ||
                       ( i->idate == tr->idate &&
                         i->message < tr->message ) ) )
            ++i;
        if ( i && i->message == tr->message )
            ;
        else if ( i )
            l->insert( i, tr );
        else
            l->append( tr );
    }

    Json * list = Json::list();
    Json * notFound = Json::list();
    uint n = 1;
    while ( n <= d->ids.count() ) {
        uint id = d->ids.value( n );
        List<ThreadRow> * l = d->threads->find( id );
        if ( l ) {
            Json * t = Json::object();
            t->insert( "id", Json::string( "t" + fn( id ) ) );
            if ( d->wantEmailIds ) {
                Json * e = Json::list();
                List<ThreadRow>::Iterator i( l );
                while ( i ) {
                    e->append( Json::string( "m" + fn( i->message ) ) );
                    ++i;
                }
                t->insert( "emailIds", e );
            }
            list->append( t );
        }
        else {
            notFound->append( Json::string( "t" + fn( id ) ) );
        }
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
    respond( "Thread/get", response );
}
