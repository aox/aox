// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "scope.h"
#include "estring.h"
#include "allocator.h"
#include "estringlist.h"
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
        if ( EString( av[i] ) == "-v" )
            verbosity++;
        else
            break;
        i++;
    }

    EStringList * args = new EStringList;
    while ( i < ac )
        args->append( new EString( av[i++] ) );

    EventLoop::setup();

    AoxCommand * cmd = AoxCommand::create( args );

    if ( !cmd ) {
        fprintf( stderr, "aox: Use 'aox help' to list commands; "
                 "and 'aox help <command>' for more.\n" );
        exit( 0 );
    }

    if ( cmd->done() )
        return 0;

    Configuration::setup( "archiveopteryx.conf" );
    Configuration::read(
        EString( "" ) +
        Configuration::compiledIn( Configuration::ConfigDir) +
        "/aoxsuper.conf", true );

    Log * l = new Log;
    Allocator::addEternal( l, "log object" );
    global.setLog( l );
    Allocator::addEternal( new StderrLogger( "aox", verbosity ),
                           "log object" );

    Configuration::report();

    if ( Scope::current()->log()->disastersYet() )
        exit( -1 );

    if ( cmd ) {
        cmd->execute();
        if ( !cmd->done() )
            EventLoop::global()->start();
        return cmd->status();
    }

    return 0;
}
