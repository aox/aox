// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "log.h"
#include "file.h"
#include "scope.h"
#include "client.h"
#include "runner.h"
#include "estring.h"
#include "logger.h"
#include "script.h"
#include "mailbox.h"
#include "database.h"
#include "eventloop.h"
#include "allocator.h"
#include "estringlist.h"
#include "stderrlogger.h"

// fstat
#include <sys/types.h>
#include <sys/stat.h>
// fprintf
#include <stdio.h>
// readdir, opendir
#include <sys/types.h>
#include <dirent.h>
// exit
#include <stdlib.h>


bool ok = true;
bool verbose = false;
bool quiet = false;
bool patient = false;
bool stopOnFailure = false;

static List<TestScript> * scripts;


static void rfile( const char * fn, bool alsoBroken )
{
    File * f = new File( fn );
    if ( !f->valid() ) {
        ok = false;
        fprintf( stderr, "whip: %s is not a valid file\n", fn );
        return;
    }
    EString c( f->contents() );
    if ( !c.startsWith( "obliterate " ) &&
         !c.startsWith( "depends " ) &&
         !c.startsWith( "# " ) ) {
        fprintf( stderr, "whip: ignoring %s\n", fn );
        return;
    }
    List<TestScript>::Iterator i( scripts );
    while ( i && i->name() != fn )
        ++i;
    if ( i )
        return;
    TestScript * s = new TestScript( f );
    if ( s->failed() ) {
        ok = false;
        return;
    }
    else if ( s->broken() && !alsoBroken ) {
        fprintf( stderr, "whip: %s is marked broken\n", fn );
        return;
    }
    if ( !s->depends().isEmpty() &&
         !TestScript::findProvider( s->depends() ) ) {
        EString pn( fn );
        int i = 0;
        while ( pn.find( '/', i ) >= i )
            i = 1 + pn.find( '/', i );
        pn = pn.mid( 0, i );
        pn.append( s->depends() );
        rfile( pn.cstr(), false );
    }
    scripts->append( s );
}


static void rdir( const char * dn )
{
    DIR * d = opendir( dn );
    if ( !d ) {
        ok = false;
        fprintf( stderr,
                 "whip: could not list the files in directory %s\n",
                 dn );
        return;
    }
    struct dirent * de = readdir( d );
    EStringList sub;
    while ( de ) {
        EString n( de->d_name );
        if ( n != "." && n != ".." )
            sub.append( EString( dn ) + "/" + n );
        de = readdir( d );
    }
    closedir( d );
    EStringList::Iterator it( sub );
    while ( it ) {
        struct stat st;
        if ( stat( it->cstr(), &st ) < 0 ) {
            fprintf( stderr, "whip: no such file: %s\n",
                     it->cstr() );
            ok = false;
        }
        else if ( it->endsWith( "~" ) ) {
            if ( verbose )
                fprintf( stderr, "whip: skipping backup file %s\n",
                         it->cstr() );
        }
        else if ( it->endsWith( "#" ) ) {
            if ( verbose )
                fprintf( stderr, "whip: skipping autosave file %s\n",
                         it->cstr() );
        }
        else if ( *it == "whip" || it->endsWith( "/whip" ) ) {
            if ( verbose )
                fprintf( stderr, "whip: skipping whip itself: %s\n",
                         it->cstr() );
        }
        else if ( *it == "core" ||
                  it->contains( "/core." ) || it->endsWith( "/core" ) ) {
            if ( verbose )
                fprintf( stderr, "whip: skipping core file %s\n",
                         it->cstr() );
        }
        else if ( S_ISDIR( st.st_mode ) ) {
            rdir( it->cstr() );
        }
        else if ( S_ISREG( st.st_mode ) ) {
            rfile( it->cstr(), false );
        }
        else {
            fprintf( stderr, "whip: ignoring %s\n", it->cstr() );
        }
        ++it;
    }
}


int main( int argc, char ** argv )
{
    Scope global;
    Logger * l = new StderrLogger( "whip", 0 );
    Allocator::addEternal( l, "/dev/zero logger" );
    global.setLog( new Log );
    EventLoop::setup();

    Configuration::setup( "archiveopteryx.conf" );
    Configuration::read( EString( "" ) +
                         Configuration::compiledIn( Configuration::ConfigDir) +
                         "/aoxsuper.conf", true );
    Configuration::add( "db-handle-interval = 3600" );

    scripts = new List<TestScript>;
    Allocator::addEternal( scripts, "global list of test scripts" );

    int i = 1;
    while ( i < argc ) {
        struct stat st;
        if ( EString( argv[i] ) == "-v" ) {
            verbose = true;
        }
        else if ( EString( argv[i] ) == "-p" ) {
            patient = true;
        }
        else if ( EString( argv[i] ) == "-q" ) {
            quiet = true;
        }
        else if ( EString( argv[i] ) == "-1" ) {
            stopOnFailure = true;
        }
        else if ( EString( argv[i] ) == "-s" ) {
            i++;
            if ( i < argc ) {
                EString s( argv[i] );
                Endpoint e( s, 143 );
                if ( !e.valid() ) {
                    fprintf( stderr, "-s specified with bad IP address.\n" );
                    exit( -1 );
                }
                TestClient::setServerAddress( s );
            }
            else {
                fprintf( stderr, "-s specified with no IP address.\n" );
                exit( -1 );
            }

        }
        else if ( stat( argv[i], &st ) < 0 ) {
            fprintf( stderr, "whip: no such file: %s\n", argv[i] );
            ok = false;
        }
        else if ( EString( argv[i] ).endsWith( "~" ) ) {
            fprintf( stderr, "whip: skipping %s\n", argv[i] );
        }
        else if ( S_ISDIR(st.st_mode) ) {
            rdir( argv[i] );
        }
        else {
            rfile( argv[i], true );
        }
        i++;
    }
    if ( !ok ) {
        fprintf( stderr,
                 "whip: exiting due to errors\n"
                 " usage: whip [-v] [-p] [-q] [-1] [-s addr] (files) (directories)\n" );
        exit( 1 );
    }
    List<TestScript>::Iterator it( scripts );
    while ( it ) {
        TestScript * p
            = TestScript::findProvider( it->depends() );
        if ( p && p->necessary() ) {
            if ( verbose )
                fprintf( stdout,
                         "skipping %s because %s implicitly runs it\n",
                         p->name().cstr(), it->name().cstr() );
            p->setNecessary( false );
        }
        ++it;
    }
    fprintf( stdout, "whip: parsed %d scripts\n", scripts->count() );
    it = scripts->first();
    while ( it ) {
        if ( it->necessary() )
            TestRunner::add( it );
        ++it;
    }

    Database::setup( 1, Database::DbOwner );
    Mailbox::setup();

    EventLoop::global()->setMemoryUsage( 256 * 1024 * 1024 );

    TestRunner::run( verbose );
    if ( TestRunner::running() )
        EventLoop::global()->start();
    fprintf( stdout, "whip: ran %d scripts\n", scripts->count() );

    int nfailed = 0;
    it = scripts->first();
    while ( it ) {
        if ( it->failed() )
            nfailed++;
        ++it;
    }
    if ( nfailed > 0 )
        printf( "whip: %d scripts failed\n", nfailed );

    bool failures = false;
    it = scripts->first();
    while ( it ) {
        if ( it->failed() ) {
            if ( !failures ) {
                printf( "whip: failing test scripts:\n" );
                failures = true;
            }
            printf( "    %s\n", it->name().cstr() );
        }
        ++it;
    }

    if ( failures )
        exit( -1 );
    exit( 0 );
}
