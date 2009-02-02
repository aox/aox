// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "estring.h"
#include "allocator.h"
#include "configuration.h"
#include "logclient.h"
#include "eventloop.h"
#include "selector.h"
#include "database.h"
#include "mailbox.h"
#include "entropy.h"
#include "searchsyntax.h"
#include "log.h"
#include "utf.h"

#include "exporter.h"

#include <stdio.h>
#include <stdlib.h>


static uint verbosity = 0;


int main( int ac, char ** av )
{
    Scope global;
    bool bad = false;

    if ( ac < 1 )
        bad = true;

    Configuration::setup( "archiveopteryx.conf" );

    EventLoop::setup();
    Log * l = new Log;
    Allocator::addEternal( l, "aoxexport log" );
    global.setLog( l );
    LogClient::setup( "aoxexport" );

    Configuration::report();

    int i = 1;
    while( i < ac && *av[i] == '-' ) {
        uint j = 1;
        while ( av[i][j] ) {
            switch( av[i][j] ) {
            case 'v':
                verbosity++;
                break;
            case 'q':
                if ( verbosity )
                    verbosity--;
                break;
            default:
                bad = true;
                break;
            }
            j++;
        }
        i++;
    }

    Utf8Codec c;
    UString source;
    if ( i >= ac )
        bad = true;
    else if ( av[i][0] == '/' )
        source = c.toUnicode( av[i++] );

    Selector * which;
    if ( i < ac ) {
        EStringList args;
        while ( i < ac )
            args.append( new EString( av[i++] ) );
        which = parseSelector( &args );
    }
    else {
        which = new Selector( Selector::NoField, Selector::All, 0 );
    }

    if ( bad ) {
        fprintf( stderr,
                 "Usage: %s [-vq] [mailbox] [search]"
                 "See aoxexport(8) or "
                 "http://aox.org/aoxexport/ for details.\n", av[0] );
        exit( -1 );
    }

    if ( !c.valid() ) {
        fprintf( stderr,
                 "%s: Mailbox name could not be converted from UTF-8: %s\n",
                 av[0],
                 c.error().cstr() );
        exit( -1 );
    }

    Entropy::setup();
    Database::setup();

    Exporter * e = new Exporter( source, which );

    Mailbox::setup( e );

    EventLoop::global()->start();

    return 0;
}
