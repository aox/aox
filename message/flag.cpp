// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "flag.h"

#include "configuration.h"
#include "transaction.h"
#include "allocator.h"
#include "eventloop.h"
#include "dbsignal.h"
#include "session.h"
#include "estring.h"
#include "scope.h"
#include "event.h"
#include "query.h"
#include "dict.h"
#include "map.h"
#include "log.h"


class FlagData
    : public EventHandler
{
public:
    FlagData( Flag * owner )
        : EventHandler(),
          that( owner ), largest( 0 ), again( false ), q( 0 ) {}

    void execute() { again = true; that->execute(); }

    Flag * that;
    Dict<uint> byName;
    Map<EString> byId;
    uint largest;
    bool again;

    Query * q;
};


static Flag * flagWatcher = 0;


/*! Constructs a Flag cache. The new object will listen for new flags
    continuously.
*/

Flag::Flag()
    : EventHandler(), d( new FlagData( this ) )
{
    setLog( new Log );
    (void)new DatabaseSignal( "flag_names_extended", d );
}


/*! Updates the RAM cache from the database table. */

void Flag::execute()
{
    if ( !d->q ) {
        d->again = false;
        d->q = new Query( "select id, name from flag_names where id > $1",
                          this );
        d->q->bind( 1, d->largest );
        d->q->execute();
    }

    while ( d->q->hasResults() ) {
        Row * r = d->q->nextRow();
        EString name = r->getEString( "name" );
        uint * id = (uint *)Allocator::alloc( sizeof(uint), 0 );
        *id = r->getInt( "id" );
        d->byName.insert( name.lower(), id );
        d->byId.insert( *id, new EString( name ) );
        if ( *id > d->largest )
            d->largest = *id;
    }
    if ( !d->q->done() )
        return;

    d->q = 0;
    if ( d->again ) {
        d->again = false;
        execute();
    }
    else {
        List<Connection> * connections = EventLoop::global()->connections();
        List<Connection>::Iterator i( connections );
        while ( i ) {
            Session * s = i->session();
            if ( s )
                s->sendFlagUpdate();
        }
        ++i;
    }
}


class FlagObliterator
    : public EventHandler
{
public:
    FlagObliterator(): EventHandler() {
        setLog( new Log );
        (void)new DatabaseSignal( "obliterated", this );
    }
    void execute() {
        ::flagWatcher->d->largest = 0;
        ::flagWatcher->d->byName.clear();
        ::flagWatcher->d->byId.clear();
        ::flagWatcher->d->again = true;
        ::flagWatcher->execute();
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
    if ( ::flagWatcher )
        return;

    ::flagWatcher = new Flag;
    ::flagWatcher->execute();
    if ( !Configuration::toggle( Configuration::Security ) )
        (void)new FlagObliterator;
}



/*! Returns the id of the flag with the given \a name, or 0 if the
    flag is not known. */

uint Flag::id( const EString & name )
{
    if ( !::flagWatcher )
        setup();

    uint * p = ::flagWatcher->d->byName.find( name.lower() );
    if ( !p )
        return 0;

    return * p;
}


/*! Returns the name of the flag with the given \a id, or an empty
    string if the flag is not known. */

EString Flag::name( uint id )
{
    if ( !::flagWatcher )
        setup();

    EString * p = ::flagWatcher->d->byId.find( id );
    if ( p )
        return *p;

    return "";
}


/*! Returns a list of all current known flags (except "\recent" of
    course), sorted by the lowercase version of their names.
*/

EStringList Flag::allFlags()
{
    if ( !::flagWatcher )
        setup();

    EStringList r;
    Map<uint>::Iterator i( ::flagWatcher->d->byName );
    while ( i ) {
        r.append( ::flagWatcher->d->byId.find( *i ) );
        ++i;
    }
    return r;
}


/*! Returns the largest ID currently used by a flag. */

uint Flag::largestId()
{
    if ( ::flagWatcher )
        return ::flagWatcher->d->largest;
    return 0;
}


static uint seenId = 0;


/*! Returns true if \a f is the "\Seen" flag and false otherwise. */

bool Flag::isSeen( uint f )
{
    if ( !::seenId )
        ::seenId = id( "\\seen" );
    return f == ::seenId;
}


static uint deletedId = 0;


/*! Returns true if \a f is the "\Deleted" flag and false otherwise. */

bool Flag::isDeleted( uint f )
{
    if ( !::deletedId )
        ::deletedId = id( "\\deleted" );
    return f == ::deletedId;
}
