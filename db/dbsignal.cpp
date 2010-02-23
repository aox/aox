// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "dbsignal.h"

#include "postgres.h"
#include "event.h"
#include "scope.h"
#include "log.h"


static List<DatabaseSignal> * signals = 0;


class DatabaseSignalData
    : public Garbage
{
public:
    DatabaseSignalData(): o( 0 ), l( new Log ) {}
    EString n;
    EventHandler * o;
    Log * l;
};


/*! \class DatabaseSignal dbsignal.h

    The DatabaseSignal class provides an interface to the PostgreSQL
    LISTEN command. By creating an instance of this class, you request
    to be notified whenever anyone uses the corresponsing pg NOTIFY
    command.

    This is an eternal object. Once you've done this, there is no
    turning back. The listening never stops.
*/


/*! Constructs a DatabaseSignal for \a name which will notify \a
    owner. Forever.
*/

DatabaseSignal::DatabaseSignal( const EString & name, EventHandler * owner )
    : Garbage(), d( new DatabaseSignalData )
{
    Scope x( d->l );
    owner->setLog( d->l );
    d->n = name;
    d->o = owner;
    if ( !signals ) {
        signals = new List<DatabaseSignal>;
        Allocator::addEternal( signals, "database notify/listen listeners" );
    }
    signals->append( this );
    log( "Listening for database signal " + name );
}


/*! This command should be called only by Postgres. It notifies those
    event handlers who have created DatabaseSignal objects for \a
    name.
*/

void DatabaseSignal::notifyAll( const EString & name )
{
    List<DatabaseSignal>::Iterator i( signals );
    while ( i ) {
        DatabaseSignal * s = i;
        ++i;
        if ( name == s->d->n && s->d->o )
            s->d->o->notify();
    }
}


/*! This destructor is private, so noone can ever call it. Objects of
    this class are indestructible by nature.
*/

DatabaseSignal::~DatabaseSignal()
{
}


/*! Returns a non-null pointer to a list of all names used with the
    constructor. This function allocates memory. The list may contain
    duplicates.
*/

EStringList * DatabaseSignal::names()
{
    EStringList * r = new EStringList;
    List<DatabaseSignal>::Iterator i( signals );
    while ( i ) {
        r->append( i->d->n );
        ++i;
    }
    return r;
}
