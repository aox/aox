// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "flag.h"

#include "string.h"
#include "query.h"
#include "scope.h"
#include "arena.h"
#include "log.h"


static List<Flag> * flags;
static Arena * arena;


class FlagFetcherData
{
public:
    FlagFetcherData(): o( 0 ), q( 0 ) {}

    EventHandler * o;
    Query * q;
};


/*! \class FlagFetcher flag.h

    The FlagFetcher class fetches all (or some) flags from the
    database. The first FlagFetcher (created by Flag::setup() in most
    cases) takes the current arena and stores all future flags into
    that Arena.
*/


/*! Constructs a FlagFetcher which will proceed to do whatever is
    smart and good. If \a owner is not null, the FlagFetcher will
    notify its \a owner when done.
*/

FlagFetcher::FlagFetcher( EventHandler * owner )
    : d( new FlagFetcherData )
{
    if ( !::arena )
        ::arena = Scope::current()->arena();
    uint n = 0;
    if ( ::flags ) {
        List<Flag>::Iterator it( ::flags->first() );
        while ( it ) {
            if ( n < it->id() )
                n = it->id();
            ++it;
        }
    }
    d->q = new Query( "select id,name from flag_names where id>" + fn( n ),
                      this );
    if ( !::flags )
        d->q->setStartUpQuery( true );
    d->q->execute();
    ::flags = new List<Flag>;
}


void FlagFetcher::execute()
{
    if ( !d->q->done() )
        return;

    Row * r = d->q->nextRow();
    while ( r ) {
        String n = r->getString( "name" );
        uint i = r->getInt( "id" );
        {
            Scope x( ::arena );
            (void)new Flag( n, i );
        }
        r = d->q->nextRow();
    }
    if ( d->o )
        d->o->notify();
}



/*! \class Flag flag.h

    The Flag class represents a single message flag, ie. a named
    binary variable that may be set on any Message.

    A Flag has a name() and an integer id(), both of which are
    unique. The id is used to store flags. There is a function to
    find() a specific flag either by name or id, and also one to get a
    list of all known flags().
*/


class FlagData {
public:
    FlagData() : id( 0 ) {}
    String name;
    uint id;
};


/*! Constructs a flag named \a name and with id \a id. Both \a name
    and \a id must be unique.
*/

Flag::Flag( const String & name, uint id )
    : d( new FlagData )
{
    d->name = name;
    d->id = id;
    if ( !::flags )
        ::flags = new List<Flag>;
    ::flags->append( this );
}


/*! Returns the name of this flag, as specified to the constructor. */

String Flag::name() const
{
    return d->name;
}


/*! Returns the id of this flag, as specified to the constructor. */

uint Flag::id() const
{
    return d->id;
}


/*! Returns a pointer to the flag named \a name, or a null pointer of
    there isn't one. The comparison is case insensitive.
*/

Flag * Flag::find( const String & name )
{
    if ( !::flags )
        return 0;
    String n = name.lower();
    List<Flag>::Iterator it( ::flags->first() );
    while ( it ) {
        if ( n == it->name().lower() )
            return it;
        ++it;
    }
    return 0;
}


/*! Returns a pointer to the flag with id \a id, or a null pointer of
    there isn't one.
*/

Flag * Flag::find( uint id )
{
    if ( !::flags )
        return 0;
    List<Flag>::Iterator it( ::flags->first() );
    while ( it ) {
        if ( it->id() == id )
            return it;
        ++it;
    }
    return 0;
}


/*! Returns a list of all known flags. The list must not be manipulated. */

const List<Flag> * Flag::flags()
{
    if ( !::flags )
        ::flags = new List<Flag>;
    return ::flags;
}


/*! Initializes the Flag subsystem, fetching all known flags from the
    database.
*/

void Flag::setup()
{
    FlagFetcher * f = new FlagFetcher( 0 );
    f->d->q->setStartUpQuery( true );
}


class FlagCreatorData {
public:
    FlagCreatorData(): owner( 0 ) {}
    EventHandler * owner;
    List<Query> queries;
};

/*! \class FlagCreator flag.h

    The FlagCreator class creates flags in the database and then
    updates the Flag index in RAM.

    When created, a FlagCreator object immediately sends queries to
    insert the necessary rows, and when that is done, it creates a
    FlagFetcher. Only when the FlagFetcher is done is the owner
    notified.
*/

/*! Constructs a FlagCreator which inserts \a flags in the database
    and notifies \a owner when the insertion is complete, both in RAM
    and in the database.
*/

FlagCreator::FlagCreator( EventHandler * owner, const StringList & flags )
    : d( new FlagCreatorData )
{
    d->owner = owner;

    StringList::Iterator it( flags.first() );
    while ( it ) {
        //log( Log::Info, "Adding new flag " + *it + " to the database" );
        Query * q = new Query( "insert into flag_names (name) values ($1)",
                               this );
        q->bind( 1, *it );
        q->execute();
        d->queries.append( q );
        ++it;
    }
}


void FlagCreator::execute()
{
    List<Query>::Iterator it( d->queries.first() );
    while ( it ) {
        List<Query>::Iterator q = it;
        ++it;
        if ( q->done() )
            d->queries.take( q );
    }
    if ( d->queries.isEmpty() )
        (void)new FlagFetcher( d->owner );
}
