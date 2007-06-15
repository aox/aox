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
#include "occlient.h"
#include "database.h"
#include "occlient.h"
#include "mailbox.h"
#include "entropy.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>


int main( int ac, char ** av )
{
    Scope global;
    bool bad = false;

    if ( ac < 3 )
        bad = true;

    Configuration::setup( "archiveopteryx.conf" );

    EventLoop::setup();
    Log * l = new Log( Log::General );
    Allocator::addEternal( l, "aoximport log" );
    global.setLog( l );
    LogClient::setup( "aoximport" );

    Configuration::report();

    int i = 1;
    while( i < ac && *av[i] == '-' ) {
        uint j = 1;
        while ( av[i][j] ) {
            switch( av[i][j] ) {
            case 'v':
                Migrator::setVerbosity( Migrator::verbosity() + 1 );
                break;
            case 'q':
                Migrator::setVerbosity( 0 );
                break;
            case 'e':
                Migrator::setErrorCopies( true );
                break;
            default:
                bad = true;
                break;
            }
            j++;
        }
        i++;
    }

    String destination;
    if ( i < ac )
        destination = av[i++];
    String mode;
    if ( i < ac )
        mode = av[i++];
    mode = mode.lower();
    Migrator * m = 0;
    if ( mode == "mbox" )
        m = new Migrator( Migrator::Mbox );
    else if ( mode == "mh" )
        m = new Migrator( Migrator::Mh );
    else if ( mode == "cyrus" )
        m = new Migrator( Migrator::Cyrus );
    else if ( mode == "maildir" )
        m = new Migrator( Migrator::Maildir );
    else
        bad = true;
    if ( m ) {
        Allocator::addEternal( m, "migrator" );
        m->setDestination( destination );
        while ( i < ac )
            m->addSource( av[i++] );
    }

    if ( bad ) {
        fprintf( stderr,
                 "Usage: %s [-vq] "
                 "<destination> <mode> <source [, source ...]>\n"
                 "See aoximport(8) for details.\n", av[0] );
        exit( -1 );
    }

    Entropy::setup();
    Database::setup();
    Mailbox::setup( m );

    OCClient::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    OCClient::setup();

    ProgressReporter * p = new ProgressReporter( m, 5 );
    // 5? command-line option?

    EventLoop::global()->start();

    p->execute();

    return m->status();
}
