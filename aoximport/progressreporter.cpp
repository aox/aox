// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "progressreporter.h"

#include "allocator.h"
#include "migrator.h"
#include "timer.h"

#include <stdio.h>
#include <time.h>


class ProgressReporterData
    : public Garbage
{
public:
    ProgressReporterData()
        : m( 0 ), t( 0 ), i( 0 ), l( 0 ), w( 0 )
        {}
    Migrator * m;
    Timer * t;
    uint i;
    uint l;
    uint w;
};


/*! \class ProgressReporter progressreporter.h

    The ProgressReporter class provides regular information on stdout
    about the import operation.
*/



/*! Constructs an object to report on the progress of \a m every \a n
    seconds.
*/

ProgressReporter::ProgressReporter( Migrator * m, uint n )
    : EventHandler(), d( new ProgressReporterData )
{
    d->m = m;
    d->t = new Timer( this, n );
    d->t->setRepeating( true );
    d->i = n;
    d->w = (uint)time( 0 );
}

/*! Reports on progress. */

void ProgressReporter::execute()
{
    uint n = d->m->messagesMigrated();
    if ( n <= d->l )
        return;
    uint w = (uint)time( 0 );
    uint p = w - d->w;
    if ( p < 1 )
        p = 1;
    fprintf( stdout,
             "Processed %d messages in %d mailboxes, %.1f/s, "
             "memory usage %s\n",
             n, d->m->mailboxesMigrated() + d->m->migrators(),
             ((double)( n - d->l )) / p ,
             String::humanNumber( Allocator::inUse() + Allocator::allocated() ).cstr() );
    d->w = w;
    d->l = n;
}

