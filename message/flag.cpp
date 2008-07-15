// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "flag.h"

#include "configuration.h"
#include "transaction.h"
#include "allocator.h"
#include "dbsignal.h"
#include "string.h"
#include "scope.h"
#include "event.h"
#include "query.h"
#include "dict.h"
#include "map.h"
#include "log.h"


static Dict<uint> * flagsByName;
static Map<String> * flagsById;
static uint largestFlagId;


class FlagFetcher
    : public EventHandler
{
public:
    FlagFetcher( EventHandler * o )
        : owner( o ), max( 0 )
    {
        q = new Query( "select id,name from flag_names "
                       "where id >= $1", this );
        q->bind( 1, ::largestFlagId );
        q->execute();
    }

    void execute()
    {
        while ( q->hasResults() ) {
            Row * r = q->nextRow();
            uint id = r->getInt( "id" );
            Flag::add( r->getString( "name" ), id );
            if ( id > max )
                max = id;
        }

        if ( !q->done() )
            return;

        ::largestFlagId = max;

        if ( owner )
            owner->execute();
    }

private:
    EventHandler * owner;
    Query * q;
    uint max;
};


class FlagCreatorData
    : public Garbage
{
public:
    FlagCreatorData( const StringList & f, Transaction * tr,
                     EventHandler * ev )
        : flags( f ), t( tr ), state( 0 ), select( 0 ),
          insert( 0 ), owner( ev ) {}
    StringList flags;
    Transaction * t;
    uint state;
    Query * select;
    Query * insert;
    EventHandler * owner;
    Dict<uint> unided;
};


/*! \class FlagCreator flag.h

    This class issuses queries using a supplied Transaction to add new
    flags to the database.
*/


/*! Starts constructing the queries needed to create the specified \a
    flags in the transaction \a t. This object will notify its \a
    owner when that is done.

    \a t will fail if flag creation fails for some reason (typically
    bugs). Transaction::error() should say what went wrong.
*/

FlagCreator::FlagCreator( const StringList & flags, Transaction * t,
                          EventHandler * owner )
    : d( new FlagCreatorData( flags, t, owner ) )
{
    execute();
}


/*! Returns true if this FlagCreator has done all it should, and false
    if it's still working.
*/

bool FlagCreator::done() const
{
    return d->state > 4;
}


/*! This private helper notifies the owner and makes sure it won't do
    so again.
*/

void FlagCreator::notify()
{
    if ( done() )
        return;
    d->state = 5;
    d->owner->notify();
}


void FlagCreator::execute()
{
    uint s = 42;
    while ( s != d->state ) {
        s = d->state;

        if ( d->state == 0 || d->state == 4 )
            selectFlags();

        if ( d->state == 1 )
            processFlags();

        if ( d->state == 2 )
            insertFlags();

        if ( d->state == 3 )
            processInsert();
    }
}

/*! This private helper issues a select to find the new flags, and
    then moves to the next state to wait for results.
*/

void FlagCreator::selectFlags()
{
    d->select = new Query( "select id, name from flag_names where "
                           "lower(name)=any($1::text[])", this );

    d->unided.clear();

    StringList sl;
    StringList::Iterator it( d->flags );
    while ( it ) {
        String name( *it );
        if ( Flag::id( name ) == 0 ) {
            String p( name.lower() );
            sl.append( p );
            d->unided.insert( p, 0 );
        }
        ++it;
    }
    d->select->bind( 1, sl );
    d->select->allowSlowness();

    if ( !sl.isEmpty() ) {
        if ( d->state == 0 )
            d->t->enqueue( new Query( "savepoint flagcreator", 0 ) );
        d->state = 1;
        d->t->enqueue( d->select );
        d->t->execute();
    }
    else if ( d->state == 4 ) {
        notify();
    }
}


/*! This private helper handles the results of selectFlags(). */

void FlagCreator::processFlags()
{
    while ( d->select->hasResults() ) {
        Row * r = d->select->nextRow();
        String name( r->getString( "name" ) );
        Flag::add( name, r->getInt( "id" ) );
        d->unided.take( name.lower() );
    }

    if ( !d->select->done() )
        return;
    d->select = 0;

    if ( d->unided.isEmpty() )
        d->state = 4;
    else
        d->state = 2;
}


/*! This private helper issues a COPY (with supporting savepoints) to
    insert the desired flags into flag_names.
*/

void FlagCreator::insertFlags()
{
    d->insert = new Query( "copy flag_names (name) from stdin with binary",
                        this );
    StringList::Iterator it( d->flags );
    while ( it ) {
        if ( d->unided.contains( it->lower() ) ) {
            d->insert->bind( 1, *it );
            d->insert->submitLine();
        }
        ++it;
    }

    d->state = 3;
    d->t->enqueue( d->insert );
    d->t->execute();
}


/*! This private helper handles the result of COPYing into
    flag_names.
*/

void FlagCreator::processInsert()
{
    if ( !d->insert->done() )
        return;

    if ( !d->insert->failed() ) {
        d->t->enqueue( new Query( "release savepoint flagcreator", this ) );
        d->state = 4;
    }
    else if ( d->insert->error().contains( "fn_uname" ) ) {
        d->t->enqueue( new Query( "rollback to flagcreator", this ) );
        d->state = 4;
    }
    else {
        // Total failure. t is now in Failed state, and there's
        // nothing we can do other than notify our owner about it.
        notify();
    }
}


class FlagObliterator
    : public EventHandler
{
public:
    FlagObliterator(): EventHandler() {
        setLog( new Log( Log::Server ) );
        (void)new DatabaseSignal( "obliterated", this );
    }
    void execute() {
        Flag::reload();
    }
};


/*! \class Flag flag.h
    Maps IMAP flag names to ids using the flag_names table.

    An IMAP flag is just a string, like "\Deleted" or "spam". RFC 3501
    defines "\Seen", "\Flagged", "\Answered", "\Draft", "\Deleted", and
    "\Recent", and clients may create other flags.

    The flag_names table contains an (id,name) map for all known flags,
    and the flags table refers to it by id. This class provides lookup
    functions by id and name.

    ("\Recent" is special; it is not stored in the flag_names table.)
*/


/*! This function must be called once from main() to set up and load
    the flag_names table. */

void Flag::setup()
{
    ::flagsByName = new Dict<uint>;
    Allocator::addEternal( ::flagsByName, "list of flags by name" );

    ::flagsById = new Map<String>;
    Allocator::addEternal( ::flagsById, "list of flags by id" );

    if ( !Configuration::toggle( Configuration::Security ) )
        (void)new FlagObliterator;

    reload();
}


/*! This function reloads the flag_names table and notifies the \a owner
    when that is finished. */

void Flag::reload( EventHandler * owner )
{
    ::largestFlagId = 0;
    ::flagsById->clear();
    ::flagsByName->clear();

    (void)new FlagFetcher( owner );
}


/*! Discards any flags that have been created by calling add() rather
    than being loaded from the database. */

void Flag::rollback()
{
    if ( !::flagsByName )
        return;

    StringList::Iterator it( ::flagsByName->keys() );
    while ( it ) {
        String k( *it );
        uint id = *::flagsByName->find( k );
        if ( id > largestFlagId ) {
            ::flagsByName->take( k );
            ::flagsById->remove( id );
        }
        ++it;
    }
}


/*! Records that a flag with the given \a name and \a id exists. After
    this call, id( \a name ) returns \a id, and name( \a id ) returns
    \a name. */

void Flag::add( const String & name, uint id )
{
    String * n = new String( name );
    n->detach();

    ::flagsById->insert( id, n );

    uint * tmp = (uint *)Allocator::alloc( sizeof(uint), 0 );
    *tmp = id;

    ::flagsByName->insert( name.lower(), tmp );
}


/*! Returns the id of the flag with the given \a name, or 0 if the
    flag is not known. */

uint Flag::id( const String & name )
{
    uint id = 0;

    if ( ::flagsByName ) {
        uint * p = ::flagsByName->find( name.lower() );
        if ( p )
            id = *p;
    }

    return id;
}


/*! Returns the name of the flag with the given \a id, or an empty
    string if the flag is not known. */

String Flag::name( uint id )
{
    String name;

    if ( ::flagsById ) {
        String * p = ::flagsById->find( id );
        if ( p )
            name = *p;
    }

    return name;
}
