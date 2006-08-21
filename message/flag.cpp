// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "flag.h"

#include "allocator.h"
#include "string.h"
#include "query.h"
#include "dict.h"
#include "map.h"
#include "log.h"


static Dict<Flag> * flagsByName;
static Map<Flag> * flagsById;
static uint largestFlagId;


class FlagFetcherData
    : public Garbage
{
public:
    FlagFetcherData(): o( 0 ), q( 0 ) {}

    EventHandler * o;
    Query * q;
};


/*! \class FlagFetcher flag.h

    The FlagFetcher class fetches all (or some) flags from the
    database.
*/


/*! Constructs a FlagFetcher which will proceed to do whatever is
    right and good. If \a owner is not null, the FlagFetcher will
    notify its \a owner when done.
*/

FlagFetcher::FlagFetcher( EventHandler * owner )
    : d( new FlagFetcherData )
{
    d->o = owner;
    // XXX: the >= in the next line may be an off-by-one. it's
    // harmless, though, since the reader checks whether such a flag
    // exists.
    d->q = new Query( "select id,name from flag_names "
                      "where id>=$1",
                      this );
    d->q->bind( 1, ::largestFlagId );
    d->q->execute();
    if ( ::flagsByName )
        return;
    ::flagsByName = new Dict<Flag>;
    Allocator::addEternal( ::flagsByName, "list of existing flags" );
    ::flagsById = new Map<Flag>;
    Allocator::addEternal( ::flagsById, "list of existing flags" );
}


class FlagData
    : public Garbage
{
public:
    FlagData() : id( 0 ) {}
    String name;
    uint id;
};


void FlagFetcher::execute()
{
    Row * r = d->q->nextRow();
    while ( r ) {
        String n = r->getString( "name" );
        uint i = r->getInt( "id" );
        // is this the only FlagFetcher working now? best to be careful
        Flag * f = Flag::find( i );
        if ( !f )
            f = new Flag( n, i );
        f->d->name = n;
        if ( i > ::largestFlagId )
            ::largestFlagId = i;
        r = d->q->nextRow();
    }
    if ( !d->q->done() )
        return;

    if ( d->o )
        d->o->execute();
}



/*! \class Flag flag.h

    The Flag class represents a single message flag, ie. a named
    binary variable that may be set on any Message.

    A Flag has a name() and an integer id(), both of which are unique.
    The id is used to store flags. There are functions to find() a
    specific flag either by name or id.
*/


/*! Constructs a flag named \a name and with id \a id. Both \a name
    and \a id must be unique.
*/

Flag::Flag( const String & name, uint id )
    : d( new FlagData )
{
    d->name = name;
    d->name.detach();
    d->id = id;
    if ( !::flagsByName )
        Flag::setup();
    ::flagsByName->insert( d->name.lower(), this );
    ::flagsById->insert( id, this );
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


/*! Returns true if this is one of the system flag, and false if this
    is a user-defined flag.

    Currently, the system flags are the ones defined in RFC 3501.
*/

bool Flag::system() const
{
    if ( d->name[0] != '\\' || d->name.length() < 5 || d->name.length() > 9 )
        return false;
    String n = d->name.mid( 1 ).lower();
    if ( n == "seen" || n == "answered" || n == "flagged" ||
         n == "deleted" || n == "draft" )
        return true;
    return false;
}


/*! Returns a pointer to the flag named \a name, or a null pointer of
    there isn't one. The comparison is case insensitive.
*/

Flag * Flag::find( const String & name )
{
    if ( !::flagsByName )
        return 0;
    return ::flagsByName->find( name.lower() );
}


/*! Returns a pointer to the flag with id \a id, or a null pointer of
    there isn't one.
*/

Flag * Flag::find( uint id )
{
    if ( !::flagsById )
        return 0;
    return ::flagsById->find( id );
}


/*! Initializes the Flag subsystem, fetching all known flags from the
    database.
*/

void Flag::setup()
{
    ::flagsByName = 0;
    ::flagsById = 0;
    ::largestFlagId = 0;
    (void)new FlagFetcher( 0 );
}


class FlagCreatorData
    : public Garbage
{
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

    StringList::Iterator it( flags );
    while ( it ) {
        Query * q = new Query( "insert into flag_names (name) values ($1)",
                               this );
        q->bind( 1, *it );
        q->allowFailure();
        q->execute();
        d->queries.append( q );
        ++it;
    }
}


void FlagCreator::execute()
{
    bool done = true;
    List<Query>::Iterator it( d->queries );
    while ( it && done ) {
        if ( !it->done() )
            done = false;
        ++it;
    }
    if ( done )
        (void)new FlagFetcher( d->owner );
}
