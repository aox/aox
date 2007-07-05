// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "servers.h"

#include "file.h"
#include "query.h"
#include "configuration.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>


static char * buildinfo[] = {
#include "buildinfo.inc"
    ""
};


static const char * servers[] = {
    "logd", "ocd", "tlsproxy", "archiveopteryx"
};
static const int nservers = sizeof( servers ) / sizeof( servers[0] );


static String pidFile( const char * s )
{
    String pf( Configuration::compiledIn( Configuration::PidFileDir ) );
    pf.append( "/" );
    pf.append( s );
    pf.append( ".pid" );
    return pf;
}


static int serverPid( const char * s )
{
    String pf = pidFile( s );
    File f( pf, File::Read );
    if ( !f.valid() )
        return -1;

    bool ok;
    int pid = f.contents().stripCRLF().number( &ok );
    if ( !ok ) {
        fprintf( stderr, "aox: Bad pid file: %s\n", pf.cstr() );
        return -1;
    }

    return pid;
}


/*! \class Start servers.h
    This class handles the "aox start" command.
*/

Start::Start( StringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void Start::execute()
{
    if ( !q ) {
        parseOptions();
        // XXX: checkFilePermissions();
        end();

        String sbin( Configuration::compiledIn( Configuration::SbinDir ) );
        if ( chdir( sbin.cstr() ) < 0 )
            error( "Couldn't chdir to SBINDIR (" + sbin + ")" );

        database();
        q = new Query( "select 42 as test", this );
        q->execute();
    }

    if ( !q->done() )
        return;

    Row * r = q->nextRow();
    if ( q->failed() || !r || r->getInt( "test" ) != 42 )
        error( "Couldn't execute a simple Postgres query: " + q->error() );

    int i = 0;
    bool started = false;
    while ( i < nservers )
        if ( startServer( servers[i++] ) )
            started = true;

    if ( !started )
        printf( "No processes need to be started.\n" );

    finish();
}


/*! Starts the server named \a s and returns true, or false if the
    server did not need to be started.
*/

bool Start::startServer( const char * s )
{
    String srv( Configuration::compiledIn( Configuration::SbinDir ) );
    srv.append( "/" );
    srv.append( s );

    bool use = true;

    String t( s );
    if ( t == "tlsproxy" )
        use = Configuration::toggle( Configuration::UseTls );
    else if ( t == "imapd" )
        use = Configuration::toggle( Configuration::UseImap ) ||
              Configuration::toggle( Configuration::UseImaps );
    else if ( t == "smtpd" )
        use = Configuration::toggle( Configuration::UseSmtp ) ||
              Configuration::toggle( Configuration::UseLmtp );
    else if ( t == "httpd" )
        use = Configuration::toggle( Configuration::UseHttp );
    else if ( t == "pop3d" )
        use = Configuration::toggle( Configuration::UsePop );

    if ( !use ) {
        if ( opt( 'v' ) > 0 )
            printf( "Don't need to start %s\n", srv.cstr() );
        return false;
    }

    int p = serverPid( s );
    if ( p != -1 ) {
        if ( kill( p, 0 ) != 0 && errno == ESRCH ) {
            File::unlink( pidFile( s ) );
        }
        else {
            if ( opt( 'v' ) > 0 )
                printf( "%s(%d) is already running\n", s, p );
            return false;
        }
    }

    if ( opt( 'v' ) > 0 )
        printf( "Starting %s\n", srv.cstr() );

    pid_t pid = fork();
    if ( pid < 0 ) {
        error( "Couldn't fork to exec(" + srv + ")" );
    }
    else if ( pid == 0 ) {
        execl( srv.cstr(), srv.cstr(), "-f", NULL );
        exit( -1 );
    }
    else {
        int status = 0;
        if ( waitpid( pid, &status, 0 ) < 0 ||
             WIFEXITED( status ) && WEXITSTATUS( status ) != 0 )
            error( "Couldn't exec(" + srv + ")" );
    }

    return true;
}



/*! \class Stop servers.h
    This class handles the "aox stop" command.
*/

Stop::Stop( StringList * args )
    : AoxCommand( args )
{
}


void Stop::execute()
{
    parseOptions();
    end();

    if ( opt( 'v' ) > 0 )
        printf( "Stopping servers: " );

    int i = 0;
    int n = 0;
    int pids[nservers];
    while ( i < nservers ) {
        pids[i] = serverPid( servers[nservers-i-1] );
        if ( opt( 'v' ) > 0 && pids[i] != -1 )
            printf( "%s%s", servers[nservers-i-1],
                    i == nservers-1 ? "" : " " );
        i++;
    }

    if ( opt( 'v' ) > 0 )
        printf( ".\n" );

    i = 0;
    while ( i < nservers ) {
        if ( pids[i] != -1 ) {
            if ( opt( 'v' ) > 1 )
                printf( "Sending SIGTERM to %d\n", pids[i] );
            File::unlink( pidFile( servers[nservers-i-1] ) );
            kill( pids[i], SIGTERM );
            n++;
        }
        i++;
    }

    if ( n > 0 ) {
        sleep( 1 );

        i = 0;
        while ( i < nservers ) {
            if ( pids[i] != -1 && kill( pids[i], 0 ) == 0 ) {
                if ( opt( 'v' ) > 1 )
                    printf( "Sending SIGKILL to %d\n", pids[i] );
                kill( pids[i], SIGKILL );
            }
            i++;
        }
    }
}



/*! \class Restart servers.h
    This class handles the "aox restart" command.
*/

Restart::Restart( StringList * args )
    : AoxCommand( args )
{
}


void Restart::execute()
{
    // XXX: checkFilePermissions();
    fprintf( stderr, "aox: restart not yet implemented.\n" );
    finish();
}



/*! \class ShowStatus servers.h
    This class handles the "aox show status" command.
*/

ShowStatus::ShowStatus( StringList * args )
    : AoxCommand( args )
{
}


void ShowStatus::execute()
{
    parseOptions();
    // XXX: checkFilePermissions();
    end();

    printf( "Servers: " );
    if ( opt( 'v' ) > 0 )
        printf( "\n  " );

    int i = 0;
    while ( i < nservers ) {
        int pid = serverPid( servers[i] );
        printf( "%s", servers[i] );

        bool started = false;
        String t( servers[i] );
        if ( t == "tlsproxy" )
            started = Configuration::toggle( Configuration::UseTls );
        else if ( t == "imapd" )
            started = Configuration::toggle( Configuration::UseImap ) ||
                      Configuration::toggle( Configuration::UseImaps );
        else if ( t == "smtpd" )
            started = Configuration::toggle( Configuration::UseSmtp ) ||
                      Configuration::toggle( Configuration::UseLmtp );
        else if ( t == "httpd" )
            started = Configuration::toggle( Configuration::UseHttp );
        else if ( t == "pop3d" )
            started = Configuration::toggle( Configuration::UsePop );

        const char * noState = started ? "not running" : "not started";

        if ( pid < 0 )
            printf( " (%s)", noState );
        else if ( kill( pid, 0 ) != 0 && errno == ESRCH )
            if ( opt( 'v' ) > 0 )
                printf( " (%s, stale pidfile)", noState );
            else
                printf( " (%s)", noState );
        else if ( opt( 'v' ) > 0 )
            printf( " (%d)", pid );

        if ( i != nservers-1 )
            if ( opt( 'v' ) > 0 )
                printf( "\n  " );
            else
                printf( ", " );
        i++;
    }

    if ( opt( 'v' ) == 0 )
        printf( "." );
    printf( "\n" );

    finish();
}



/*! \class ShowBuild servers.h
    This class handles the "aox show build" command.
*/

ShowBuild::ShowBuild( StringList * args )
    : AoxCommand( args )
{
}


void ShowBuild::execute()
{
    end();

    printf( "Archiveopteryx version %s, "
            "http://www.archiveopteryx.org/%s.html\n",
            Configuration::compiledIn( Configuration::Version ),
            Configuration::compiledIn( Configuration::Version ) );

    printf( "Built on " __DATE__ " " __TIME__ "\n" );

    int i = 0;
    while ( buildinfo[i] && *buildinfo[i] )
        printf( "%s\n", buildinfo[i++] );

    printf( "Jamsettings:\n" );
    printf( "CONFIGDIR = %s\n",
            Configuration::compiledIn( Configuration::ConfigDir ) );
    printf( "PIDFILEDIR = %s\n",
            Configuration::compiledIn( Configuration::PidFileDir ) );
    printf( "BINDIR = %s\n",
            Configuration::compiledIn( Configuration::BinDir ) );
    printf( "MANDIR = %s\n",
            Configuration::compiledIn( Configuration::ManDir ) );
    printf( "LIBDIR = %s\n",
            Configuration::compiledIn( Configuration::LibDir ) );
    printf( "INITDIR = %s\n",
            Configuration::compiledIn( Configuration::InitDir ) );
    printf( "AOXUSER = %s\n",
            Configuration::compiledIn( Configuration::OryxUser ) );
    printf( "AOXGROUP = %s\n",
            Configuration::compiledIn( Configuration::OryxGroup ) );
    printf( "VERSION = %s\n",
            Configuration::compiledIn( Configuration::Version ) );

    finish();
}



/*! \class ShowConfiguration servers.h
    This class handles the "aox show configuration" command.
*/

ShowConfiguration::ShowConfiguration( StringList * args )
    : AoxCommand( args )
{
}


void ShowConfiguration::execute()
{
    SortedList<String> output;

    parseOptions();
    String pat = next();
    end();

    uint i = 0;
    while ( i < Configuration::NumScalars ) {
        Configuration::Scalar j = (Configuration::Scalar)i++;

        String n( Configuration::name( j ) );
        String v( fn( Configuration::scalar( j ) ) );
        addVariable( &output, n, v, pat, Configuration::present( j ) );
    }

    i = 0;
    while ( i < Configuration::NumToggles ) {
        Configuration::Toggle j = (Configuration::Toggle)i++;

        String n( Configuration::name( j ) );
        String v( Configuration::toggle( j ) ? "on" : "off" );
        addVariable( &output, n, v, pat, Configuration::present( j ) );
    }

    i = 0;
    while ( i < Configuration::NumTexts ) {
        Configuration::Text j = (Configuration::Text)i++;

        String n( Configuration::name( j ) );
        String v( Configuration::text( j ) );
        if ( j != Configuration::DbPassword &&
             j != Configuration::DbOwnerPassword ) {
            if ( v.isEmpty() )
                v = "\"\"";
            addVariable( &output, n, v, pat, Configuration::present( j ) );
        }
    }

    StringList::Iterator it( output );
    while ( it ) {
        printf( "%s\n", it->cstr() );
        ++it;
    }

    finish();
}


/*! Adds the variable named \a n with value \a v to the output list
    \a l if it matches \a pat and is explicitly \a mentioned.
*/

void ShowConfiguration::addVariable( SortedList< String > * l,
                                     String n, String v, String pat,
                                     bool mentioned )
{
    int np = opt( 'p' );
    int nv = opt( 'v' );

    if ( ( pat.isEmpty() || n == pat ) &&
         ( np == 0 || mentioned ) )
    {
        String * s = new String;

        if ( nv == 0 ) {
            s->append( n );
            s->append( " = " );
        }
        s->append( v );
        l->insert( s );
    }
}
