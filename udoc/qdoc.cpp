// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sourcefile.h"
#include "intro.h"
#include "class.h"
#include "scope.h"
#include "arena.h"
#include "error.h"
#include "webpage.h"
#include "manpage.h"
#include "postscript.h"
#include "sys.h"

#include <stdio.h> // fprintf()


// nostalgia in a filename


int main( int argc, char ** argv )
{
    Arena arena;
    Scope global( &arena );

    ManPage * mp = 0;
    WebPage * wp = 0;
    Postscript * ps = 0;

    int i = 1;
    while ( i < argc ) {
        if ( argv[i][0] != '-' ) {
            (void)new SourceFile( argv[i] );
        }
        else if ( argv[i][2] == '\0' && i+1 < argc ) {
            switch( argv[i][1] ) {
            case 'm':
                if ( mp )
                    fprintf( stderr, "udoc: -m specified twice\n" );
                mp = new ManPage( argv[++i] );
                break;
            case 'w':
                if ( wp )
                    fprintf( stderr, "udoc: -w specified twice\n" );
                wp = new WebPage( argv[++i] );
                break;
            case 'p':
                if ( ps )
                    fprintf( stderr, "udoc: -p specified twice\n" );
                ps = new Postscript( argv[++i] );
                break;
            case 'o':
                if ( !Output::owner().isEmpty() )
                    fprintf( stderr, "udoc: -o specified twice" );
                Output::setOwner( argv[++i] );
                break;
            case 'u':
                if ( !Output::ownerHome().isEmpty() )
                    fprintf( stderr, "udoc: -u specified twice" );
                Output::setOwnerHome( argv[++i] );
                break;
            default:
                fprintf( stderr, "udoc: don't understand %s\n",
                         argv[i] );
                exit( 1 );
                break;
            }
        }
        else {
            fprintf( stderr, "udoc: cannot parse option %d: %s\n",
                     i, argv[i] );
            exit( 1 );
        }
        i++;
    }

    if ( !mp && !wp && !ps ) {
        fprintf( stderr, "udoc: no output specified\n" );
        exit( 1 );
    }

    Class::buildHierarchy();

    Intro::output();
    Class::output();

    delete mp;
    delete wp;
    delete ps;

    Error::report();
    return 0;
}


/*! \chapter index

    \introduces HeaderFile SourceFile

    \introduces ManPage Output Postscript WebPage

    \introduces Class Function Intro

    \introduces DocBlock

    \introduces Error Parser Singleton

*/
