// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "addresscache.h"

#include "transaction.h"
#include "allocator.h"
#include "scope.h"
#include "event.h"
#include "query.h"
#include "address.h"
#include "dict.h"
#include "list.h"
#include "map.h"


static Map< Address > *idCache;
static Dict< Address > *nameCache;
static PreparedStatement *addressLookup;
static PreparedStatement *addressInsert;


/*! \class AddressCache addresscache.h
    This class maintains a cache of the addresses in the database.

    This class is responsible for finding the numeric id of an Address
    object. It may find the id in its in-memory cache, or by issuing a
    SELECT against the addresses table, or, failing that, by inserting
    a new row into the table and retrieving its id.

    (...We want to describe the id-lookups here...)

    Each entry in the addresses table must be unique. Instead of using
    an explicit lock to serialise insertions by multiple Injectors, we
    simply add a UNIQUE(name, address, localpart) clause to the table,
    and allow duplicate INSERTs to fail.

    (...We need to talk about synchronisation through ocd here...)

    This class is used only by the Injector at present.
*/

/*! This function initialises the cache of Address objects at startup.
    It expects to be called from ::main().
*/

void AddressCache::setup()
{
    // The idCache maps numeric ids to their corresponding Addresses,
    // and the nameCache maps a string representation of each address
    // to the same set of objects.

    idCache = new Map< Address >;
    Allocator::addEternal( idCache, "address cache (id)" );
    nameCache = new Dict< Address >;
    Allocator::addEternal( nameCache, "address cache (name)" );

    // The first query is used to resolve cache misses. If the address
    // doesn't exist in the table, the other query inserts it.

    addressLookup =
        new PreparedStatement( "select id from addresses where "
                               "name=$1 and localpart=$2 and domain=$3" );
    addressInsert =
        new PreparedStatement( "insert into addresses(name,localpart,domain) "
                               "values ($1,$2,$3)" );

    Allocator::addEternal( addressInsert, "address insertion statement" );
    Allocator::addEternal( addressLookup, "address lookup statement" );
}


class AddressLookup
    : public EventHandler
{
protected:
    Query *q;
    Address *address;
    CacheLookup *status;
    EventHandler *owner;
    List< Query > *queries;
    Transaction *transaction;

public:
    AddressLookup() {}
    AddressLookup( Transaction *t, Address *a, List< Query > *l,
                   CacheLookup *st, EventHandler *ev )
        : address( a ), status( st ), owner( ev ), queries( l ),
          transaction( t )
    {
        q = new Query( *addressLookup, this );
        q->bind( 1, a->name() );
        q->bind( 2, a->localpart() );
        q->bind( 3, a->domain() );
        transaction->enqueue( q );
        l->append( q );
    }

    void execute();
};


class AddressInsert
    : public AddressLookup
{
public:
    AddressInsert( Transaction *t, Address *a, List< Query > *l,
                   CacheLookup *st, EventHandler *ev )
    {
        address = a;
        status = st;
        owner = ev;
        queries = l;
        transaction = t;

        Query *i = new Query( *addressInsert, this );
        i->bind( 1, a->name() );
        i->bind( 2, a->localpart() );
        i->bind( 3, a->domain() );
        transaction->enqueue( i );

        q = new Query( *addressLookup, this );
        q->bind( 1, a->name() );
        q->bind( 2, a->localpart() );
        q->bind( 3, a->domain() );
        transaction->enqueue( q );
        l->append( q );

        transaction->execute();
    }
};


void AddressLookup::execute() {
    if ( !q->done() )
        return;

    Row *r = q->nextRow();
    delete queries->take( queries->find( q ) );

    if ( !r ) {
        // It may be better to collect INSERTs and execute them together
        // on one database handle after processing the SELECTs. We don't
        // bother yet.
        (void)new AddressInsert( transaction, address, queries, status,
                                 owner );
        return;
    }

    uint id = r->getInt( "id" );
    address->setId( id );
    Address *a = new Address( address->name(), address->localpart(),
                              address->domain() );
    a->setId( id );

    idCache->insert( a->id(), a );
    nameCache->insert( a->toString(), a );

    if ( queries->isEmpty() ) {
        status->setState( CacheLookup::Completed );
        owner->execute();
    }
}


/*! This function accepts the List \a l of Address objects, and notifies
    \a ev after it has called Address::setId() for each Address in \a l.
    Cached addresses will be resolved immediately. Uncached ones incur a
    database lookup, and possibly an insert followed by a select, before
    being added to the cache.

    Any required queries will be run in the Transaction \a t.

    (We assume, for the moment, that none of the queries will fail.)
*/

CacheLookup *AddressCache::lookup( Transaction *t, List< Address > *l,
                                   EventHandler *ev )
{
    // We step through l, resolving cached addresses, and adding queries
    // for the others to this List:
    List< Query > * lookups = new List< Query >;
    CacheLookup * status = new CacheLookup;

    List< Address >::Iterator it( l->first() );
    while ( it ) {
        Address *a = nameCache->find( it->toString() );

        if ( !a )
            (void)new AddressLookup( t, it, lookups, status, ev );
        else
            it->setId( a->id() );

        ++it;
    }

    if ( lookups->isEmpty() )
        status->setState( CacheLookup::Completed );
    else
        t->execute();

    return status;
}
