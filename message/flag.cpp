// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "flag.h"

#include "transaction.h"
#include "allocator.h"
#include "dbsignal.h"
#include "string.h"
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


class FlagCreator
    : public EventHandler
{
public:
    StringList flags;
    Transaction * t;
    int state;
    Query * q;
    Query * result;
    Dict<uint> unided;
    int savepoint;

    FlagCreator( const StringList & f, Transaction * tr, EventHandler * ev )
        : flags( f ), t( tr ),
          state( 0 ), q( 0 ), savepoint( 0 )
    {
        result = new Query( ev );
    }

    void execute();
    void selectFlags();
    void processFlags();
    void insertFlags();
    void processInsert();
};

void FlagCreator::execute()
{
    if ( state == 0 )
        selectFlags();

    if ( state == 1 )
        processFlags();

    if ( state == 2 )
        insertFlags();

    if ( state == 3 )
        processInsert();

    if ( state == 4 ) {
        state = 42;
        if ( !result->done() )
            result->setState( Query::Completed );
        result->notify();
    }
}

void FlagCreator::selectFlags()
{
    q = new Query( "", this );

    String s( "select id, name from flag_names where " );

    unided.clear();

    uint i = 0;
    StringList sl;
    StringList::Iterator it( flags );
    while ( it ) {
        String name( *it );
        if ( Flag::id( name ) == 0 ) {
            ++i;
            String p;
            q->bind( i, name.lower() );
            p.append( "lower(name)=$" );
            p.append( fn( i ) );
            unided.insert( name.lower(), 0 );
            sl.append( p );
        }
        ++it;
    }
    s.append( sl.join( " or " ) );
    q->setString( s );
    q->allowSlowness();

    if ( i == 0 ) {
        state = 4;
    }
    else {
        state = 1;
        t->enqueue( q );
        t->execute();
    }
}

void FlagCreator::processFlags()
{
    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        String name( r->getString( "name" ) );
        Flag::add( name, r->getInt( "id" ) );
        unided.take( name.lower() );
    }

    if ( !q->done() )
        return;

    if ( unided.isEmpty() ) {
        state = 0;
        selectFlags();
    }
    else {
        state = 2;
    }
}

void FlagCreator::insertFlags()
{
    q = new Query( "savepoint c" + fn( savepoint ), this );
    t->enqueue( q );

    q = new Query( "copy flag_names (name) from stdin with binary", this );
    StringList::Iterator it( unided.keys() );
    while ( it ) {
        q->bind( 1, *it, Query::Binary );
        q->submitLine();
        ++it;
    }

    state = 3;
    t->enqueue( q );
    t->execute();
}

void FlagCreator::processInsert()
{
    if ( !q->done() )
        return;

    state = 0;
    if ( q->failed() ) {
        if ( q->error().contains( "fn_uname" ) ) {
            q = new Query( "rollback to c" + fn( savepoint ), this );
            t->enqueue( q );
            savepoint++;
        }
        else {
            result->setState( Query::Failed );
            state = 4;
        }
    }
    else {
        q = new Query( "release savepoint c" + fn( savepoint ), this );
        t->enqueue( q );
    }

    if ( state == 0 )
        selectFlags();
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


/*! Issues the queries needed to create the specified \a flags in the
    transaction \a t and notifies the \a owner when that is done, i.e.
    when id() and name() recognise the newly-created flags.
*/

Query * Flag::create( const StringList & flags, Transaction * t,
                      EventHandler * owner )
{
    return (new FlagCreator( flags, t, owner ))->result;
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
