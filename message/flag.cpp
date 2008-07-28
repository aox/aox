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


/*! Returns a list of all current known flags (except "\recent" of
    course), sorted by id().
*/

StringList Flag::allFlags()
{
    StringList r;
    uint i = 0;
    while ( i <= ::largestFlagId ) {
        String * n = ::flagsById->find( i );
        if ( n )
            r.append( n );
        ++i;
    }
    return r;
}
