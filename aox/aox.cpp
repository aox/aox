// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "allocator.h"
#include "stringlist.h"
#include "configuration.h"
#include "stderrlogger.h"
#include "aoxcommand.h"
#include "eventloop.h"
#include "logger.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>


/*! \nodoc */


int main( int ac, char *av[] )
{
    Scope global;

    av++;
    ac--;

    uint verbosity = 0;

    int i = 0;
    while ( i < ac ) {
        if ( String( av[i] ) == "-v" )
            verbosity++;
        else
            break;
        i++;
    }

    StringList * args = new StringList;
    while ( i < ac )
        args->append( new String( av[i++] ) );

    EventLoop::setup();

    Configuration::setup( "archiveopteryx.conf" );
    Configuration::read( String( "" ) +
                         Configuration::compiledIn( Configuration::ConfigDir) +
                         "/aoxsuper.conf", true );

    Log * l = new Log( Log::General );
    Allocator::addEternal( l, "log object" );
    global.setLog( l );
    Allocator::addEternal( new StderrLogger( "aox", verbosity ),
                           "log object" );

    Configuration::report();

    if ( Scope::current()->log()->disastersYet() )
        exit( -1 );

    AoxCommand * cmd = AoxCommand::create( args );
    if ( cmd ) {
        cmd->execute();
        if ( !cmd->done() )
            EventLoop::global()->start();
        return cmd->status();
    }

    return 0;
}
