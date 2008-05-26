// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "dbsignal.h"

#include "event.h"
#include "scope.h"
#include "list.h"


static List<DatabaseSignal> * signals = 0;


class DatabaseSignalData
    : public Garbage
{
public:
    DatabaseSignalData(): o( 0 ) {}
    String n;
    EventHandler * o;
};


/*! \class DatabaseSignal dbsignal.h

    The DatabaseSignal class provides an interface to the PostgreSQL
    LISTEN command. By creating an instance of this class, you request
    to be notified whenever anyone uses the corresponsing gp NOTIFY
    command.

    This is an eternal object. Once you've done this, there is no
    turning back. The listening never stops.
*/


/*! Constructs a DatabaseSignal for \a name which will notified \a
    owner. Forever.
*/

DatabaseSignal::DatabaseSignal( const String & name, EventHandler * owner )
    : Garbage(), d( new DatabaseSignalData )
{
    d->n = name;
    d->o = owner;
    if ( !signals ) {
        signals = new List<DatabaseSignal>;
        Allocator::addEternal( signals, "database notify/listen listeners" );
    }
    signals->append( this );
}


/*! This command should be called only by Postgres. It notifies those
    event handlers who have created DatabaseSignal objects for \a
    name.
*/

void DatabaseSignal::notifyAll( const String & name )
{
    List<DatabaseSignal>::Iterator i( signals );
    while ( i ) {
        DatabaseSignal * s = i;
        ++i;
        if ( name == s->d->n && s->d->o ) {
            Scope x( s->d->o->log() );
            s->d->o->execute();
        }
    }
}


/*! This destructor is private, so noone can ever call it. Objects of
    this class are indestructible by nature.
*/

DatabaseSignal::~DatabaseSignal()
{
}
