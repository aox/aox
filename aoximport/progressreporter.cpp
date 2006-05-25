// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "progressreporter.h"

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

    The ProgressReporter class privides regular information on stdout
    about the import operation.
*/



/*! Constructs an object to report on the progress of \a m every \a n seconds. */

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
             "Processed %4d messages in %4d mailboxes, %.1f/s\n",
             n, d->m->mailboxesMigrated() + d->m->migrators(),
             ((double)( n - d->l )) / d->i );
    d->l = n;
}

