// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "migrator.h"
#include "allocator.h"
#include "configuration.h"
#include "progressreporter.h"
#include "addresscache.h"
#include "fieldcache.h"
#include "logclient.h"
#include "eventloop.h"
#include "database.h"
#include "occlient.h"
#include "mailbox.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>


int main( int ac, char ** av )
{
    Scope global;

    if ( ac < 3 ) {
        fprintf( stderr, "Usage: %s <destination> <mode> <source [, source ...]>\n"
                 "See aoximport(8) for details.\n", av[0] );
        exit( -1 );
    }

    Configuration::setup( "archiveopteryx.conf" );

    EventLoop::setup();
    Log * l = new Log( Log::General );
    Allocator::addEternal( l, "aoximport log" );
    global.setLog( l );
    LogClient::setup( "aoximport" );

    Configuration::report();

    Migrator * m = 0;
    String mode = av[2];
    mode = mode.lower();
    if ( mode == "mbox" ) {
        m = new Migrator( Migrator::Mbox );
    }
    else if ( mode == "mh" ) {
        m = new Migrator( Migrator::Mh );
    }
    else if ( mode == "cyrus" ) {
        m = new Migrator( Migrator::Cyrus );
    }
    else {
        fprintf( stderr, "Usage: %s <destination> <mode> <source [, source ...]>\n"
                 "Possible modes are mbox, cyrus and mh.\n"
                 "See aoximport(8) for details.\n", av[0] );
        exit( -1 );
    }
    Allocator::addEternal( m, "migrator" );

    m->setDestination( av[1] );
    int i = 3;
    while ( i < ac )
        m->addSource( av[i++] );

    Database::setup();
    Mailbox::setup( m );

    OCClient::setup();
    AddressCache::setup();
    FieldNameCache::setup();

    ProgressReporter * p = new ProgressReporter( m, 5 );
    // 5? command-line option?

    EventLoop::global()->start();

    p->execute();

    return m->status();
}
