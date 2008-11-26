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
    Map<String> byId;
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
        d->q = new Query( "select id, name from flag_names where id >= $1",
                          this );
        d->q->bind( 1, d->largest );
        d->q->execute();
    }
    while ( d->q->hasResults() ) {
        Row * r = d->q->nextRow();
        String name = r->getString( "name" );
        uint * id = (uint *)Allocator::alloc( sizeof(uint), 0 );
        *id = r->getInt( "id" );
        d->byName.insert( name.lower(), id );
        d->byId.insert( *id, new String( name ) );
        if ( *id > d->largest )
            d->largest = *id;
    }
    if ( d->q->done() ) {
        d->q = 0;
        if ( d->again ) {
            d->again = false;
            execute();
        }
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

uint Flag::id( const String & name )
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

String Flag::name( uint id )
{
    if ( !::flagWatcher )
        setup();

    String * p = ::flagWatcher->d->byId.find( id );
    if ( p )
        return *p;

    return "";
}


/*! Returns a list of all current known flags (except "\recent" of
    course), sorted by the lowercase version of their names.
*/

StringList Flag::allFlags()
{
    if ( !::flagWatcher )
        setup();

    StringList r;
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
