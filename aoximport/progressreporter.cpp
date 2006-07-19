// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "progressreporter.h"

#include "allocator.h"
#include "migrator.h"
#include "timer.h"

#include <stdio.h>


class ProgressReporterData
    : public Garbage
{
public:
    ProgressReporterData()
        : m( 0 ), t( 0 ), i( 0 ), l( 0 )
        {}
    Migrator * m;
    Timer * t;
    uint i;
    uint l;
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
}


/*! Reports on progress. */

void ProgressReporter::execute()
{
    uint n = d->m->messagesMigrated();
    fprintf( stdout,
             "Processed %d messages in %d mailboxes, %.1f/s, "
             "memory usage %s+%s\n",
             n, d->m->mailboxesMigrated() + d->m->migrators(),
             ((double)( n - d->l )) / d->i,
             String::humanNumber( Allocator::inUse() ).cstr(),
             String::humanNumber( Allocator::allocated() ).cstr() );
    d->l = n;
}

