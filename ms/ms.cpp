// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "stringlist.h"
#include "configuration.h"
#include "file.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>


char * ms;
StringList * args;
int options[256];
int status;


char * servers[] = {
    "logd", "ocd", "tlsproxy", "imapd", "smtpd", "httpd"
};
const int nservers = sizeof( servers ) / sizeof( servers[0] );


String next();
int opt( char );
void bad( String, String );
void error( String );
void parseOptions();
void end();

void start();
void stop();
void restart();
void showStatus();
void showBuildconf();
void showConfiguration();
void migrate();
void createUser();
void deleteUser();
void createMailbox();
void deleteMailbox();
void changePassword();
void listUsers();
void help();


/*! \nodoc */


int main( int ac, char *av[] )
{
    Scope global;

    args = new StringList;
    ms = *av++;
    ac--;

    int i = 0;
    while ( i < ac )
        args->append( new String( av[i++] ) );

    Configuration::setup( "mailstore.conf" );
    Configuration::report();

    if ( Scope::current()->log()->disastersYet() )
        exit( -1 );

    String verb = next().lower();
    if ( verb == "start" ) {
        start();
    }
    else if ( verb == "stop" ) {
        stop();
    }
    else if ( verb == "restart" ) {
        restart();
    }
    else if ( verb == "show" ) {
        String noun = next().lower();
        if ( noun == "status" )
            showStatus();
        else if ( noun == "build" || noun == "buildconf" )
            showBuildconf();
        else if ( noun == "cf" || noun == "conf" || noun == "config" ||
                  noun == "configuration" )
            showConfiguration();
        else
            bad( verb, noun );
    }
    else if ( verb == "migrate" ) {
        migrate();
    }
    else if ( verb == "create" || verb == "add" || verb == "new" ) {
        String noun = next().lower();
        if ( noun == "user" )
            createUser();
        else if ( noun == "mailbox" )
            createMailbox();
        else
            bad( verb, noun );
    }
    else if ( verb == "delete" || verb == "del" || verb == "remove" ) {
        String noun = next().lower();
        if ( noun == "user" )
            createUser();
        else if ( noun == "mailbox" )
            createMailbox();
        else
            bad( verb, noun );
    }
    else if ( verb == "change" ) {
        String noun = next().lower();
        if ( noun == "password" )
            changePassword();
        else
            bad( verb, noun );
    }
    else if ( verb == "list" ) {
        String noun = next().lower();
        if ( noun == "users" )
            listUsers();
        else
            bad( verb, noun );
    }
    else {
        if ( verb != "help" )
            args->prepend( new String( verb ) );
        help();
    }

    return status;
}


String next()
{
    if ( args->isEmpty() )
        return "";
    return *args->shift();
}


int opt( char c )
{
    return options[(int)c];
}


void bad( String verb, String noun )
{
    if ( noun.isEmpty() )
        fprintf( stderr, "ms %s: No argument supplied.\n",
                 verb.cstr() );
    else
        fprintf( stderr, "ms %s: Unknown argument: %s.\n",
                 verb.cstr(), noun.cstr() );
    exit( -1 );
}


void error( String m )
{
    fprintf( stderr, "ms: %s\n", m.cstr() );
    exit( -1 );
}


void parseOptions()
{
    StringList::Iterator it( args );
    while ( it ) {
        String s = *it;
        if ( s[0] != '-' )
            break;
        if ( s.length() == 2 &&
             ( ( s[1] >= '0' && s[1] <= '9' ) ||
               ( s[1] >= 'A' && s[1] <= 'Z' ) ||
               ( s[1] >= 'a' && s[1] <= 'z' ) ) )
            options[(int)s[1]]++;
        else
            error( "Bad option name: '" + s + "'" );
        args->take( it );
    }
}


void end()
{
    if ( args->isEmpty() )
        return;
    error( "Unexpected argument: " + next() );
}


void startServer( const char *s )
{
    String srv( Configuration::compiledIn( Configuration::SbinDir ) );
    srv.append( "/" );
    srv.append( s );

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
}


void start()
{
    parseOptions();
    end();

    String sbin( Configuration::compiledIn( Configuration::SbinDir ) );
    if ( chdir( sbin.cstr() ) < 0 )
        error( "Couldn't chdir to SBINDIR (" + sbin + ")" );

    int i = 0;
    while ( i < nservers )
        startServer( servers[i++] );
}


String pidFile( const char *s )
{
    String pf( Configuration::compiledIn( Configuration::PidFileDir ) );
    pf.append( "/" );
    pf.append( s );
    pf.append( ".pid" );
    return pf;
}


int serverPid( const char *s )
{
    String pf = pidFile( s );
    File f( pf, File::Read );
    if ( !f.valid() )
        return -1;

    bool ok;
    int pid = f.contents().stripCRLF().number( &ok );
    if ( !ok ) {
        fprintf( stderr, "ms: Bad pid file: %s\n", pf.cstr() );
        return -1;
    }

    return pid;
}


void stop()
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


void restart()
{
    parseOptions();
    end();

    stop();
    sleep( 1 );
    start();
}


void showStatus()
{
    parseOptions();
    end();

    printf( "Servers: " );
    if ( opt( 'v' ) > 0 )
        printf( "\n  " );

    int i = 0;
    while ( i < nservers ) {
        int pid = serverPid( servers[i] );
        printf( "%s", servers[i] );
        if ( pid < 0 )
            printf( " (not running)" );
        else if ( kill( pid, 0 ) != 0 && errno == ESRCH )
            if ( opt( 'v' ) > 0 )
                printf( " (not running, stale pidfile)" );
            else
                printf( " (not running)" );
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
}


void showBuildconf()
{
    end();

    printf( "Built on " __DATE__ " " __TIME__ "\n" );
    printf( "CONFIGDIR = %s\n",
            Configuration::compiledIn( Configuration::ConfigDir ).cstr() );
    printf( "PIDFILEDIR = %s\n",
            Configuration::compiledIn( Configuration::PidFileDir ).cstr() );
    printf( "BINDIR = %s\n",
            Configuration::compiledIn( Configuration::BinDir ).cstr() );
    printf( "MANDIR = %s\n",
            Configuration::compiledIn( Configuration::ManDir ).cstr() );
    printf( "LIBDIR = %s\n",
            Configuration::compiledIn( Configuration::LibDir ).cstr() );
    printf( "INITDIR = %s\n",
            Configuration::compiledIn( Configuration::InitDir ).cstr() );
    printf( "ORYXUSER = %s\n",
            Configuration::compiledIn( Configuration::OryxUser ).cstr() );
    printf( "ORYXGROUP = %s\n",
            Configuration::compiledIn( Configuration::OryxGroup ).cstr() );
    printf( "VERSION = %s\n",
            Configuration::compiledIn( Configuration::Version ).cstr() );
}


void addVariable( SortedList< String > *l, String n, String v,
                  String pat, bool p )
{
    int np = opt( 'p' );
    int nv = opt( 'v' );

    if ( ( pat.isEmpty() || n == pat ) &&
         ( np == 0 || p ) )
    {
        String *s = new String;

        if ( nv == 0 ) {
            s->append( n );
            s->append( " = " );
        }
        s->append( v );
        l->insert( s );
    }
}


void showConfiguration()
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
        if ( j != Configuration::DbPassword ) {
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
}


void migrate()
{
    fprintf( stderr, "ms migrate: Not yet implemented.\n" );
}


void createUser()
{
    fprintf( stderr, "ms create user: Not yet implemented.\n" );
}


void deleteUser()
{
    fprintf( stderr, "ms delete user: Not yet implemented.\n" );
}


void createMailbox()
{
    fprintf( stderr, "ms create mailbox: Not yet implemented.\n" );
}


void deleteMailbox()
{
    fprintf( stderr, "ms delete mailbox: Not yet implemented.\n" );
}


void changePassword()
{
    fprintf( stderr, "ms change password: Not yet implemented.\n" );
}


void listUsers()
{
    fprintf( stderr, "ms list users: Not yet implemented.\n" );
}


void help()
{
    String a = next().lower();
    String b = next().lower();

    // We really need a better way of constructing help texts.
    // (And better help text, now that I think about it.)

    if ( a == "start" ) {
        fprintf(
            stderr,
            "  start -- Start the servers.\n\n"
            "    Synopsis: ms start [-v]\n\n"
            "    Starts the Oryx servers in the correct order.\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "stop" ) {
        fprintf(
            stderr,
            "  stop -- Stop the running servers.\n\n"
            "    Synopsis: ms stop [-v]\n\n"
            "    Stops the running Oryx servers in the correct order.\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "restart" ) {
        fprintf(
            stderr,
            "  restart -- Restart the servers.\n\n"
            "    Synopsis: ms restart [-v]\n\n"
            "    Restarts the Oryx servers in the correct order.\n"
            "    (Currently equivalent to start && stop.)\n\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "show" && b == "status" ) {
        fprintf(
            stderr,
            "  show status -- Display a summary of the running servers.\n\n"
            "    Synopsis: ms show status [-v]\n\n"
            "    Displays a summary of the running Oryx servers.\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "show" && ( b == "cf" || b.startsWith( "conf" ) ) ) {
        fprintf(
            stderr,
            "  show configuration -- Display configuration variables.\n\n"
            "    Synopsis: ms show conf [ -p -v ] [variable-name]\n\n"
            "    Displays variables configured in mailstore.conf.\n\n"
            "    If a variable-name is specified, only that variable\n"
            "    is displayed.\n\n"
            "    The -v flag displays only the value of the variable.\n"
            "    The -p flag restricts the results to variables whose\n"
            "    value has been changed from the default.\n\n"
            "    Examples:\n\n"
            "      ms show configuration\n"
            "      ms show config -p\n"
            "      ms show conf use-\n"
            "      ms show cf -v imap-address\n"
        );
    }
    else if ( a == "show" && b.startsWith( "build" ) ) {
        fprintf(
            stderr,
            "  show build -- Display build settings.\n\n"
            "    Synopsis: ms show build\n\n"
            "    Displays the build settings used for this installation.\n"
            "    (As configured in Jamsettings.)\n"
        );
    }
    else {
        fprintf( stderr, "Usage: %s <verb> <noun> [arguments]\n", ms );
    }
}
