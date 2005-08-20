// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "allocator.h"
#include "stringlist.h"
#include "configuration.h"
#include "addresscache.h"
#include "database.h"
#include "occlient.h"
#include "address.h"
#include "mailbox.h"
#include "schema.h"
#include "query.h"
#include "file.h"
#include "loop.h"
#include "user.h"
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
class Receiver * r;


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
void showSchema();
void upgradeSchema();
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

    Loop::setup();
    Configuration::setup( "mailstore.conf" );
    Configuration::report();

    if ( Scope::current()->log()->disastersYet() )
        exit( -1 );

    String verb = next().lower();

    if ( verb == "add" || verb == "new" )
        verb = "create";
    else if ( verb == "del" || verb == "remove" )
        verb = "delete";

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
        else if ( noun == "build" )
            showBuildconf();
        else if ( noun == "cf" || noun == "configuration" )
            showConfiguration();
        else if ( noun == "schema" )
            showSchema();
        else
            bad( verb, noun );
    }
    else if ( verb == "upgrade" ) {
        String noun = next().lower();
        if ( noun == "schema" )
            upgradeSchema();
        else
            bad( verb, noun );
    }
    else if ( verb == "create" || verb == "delete" ) {
        String noun = next().lower();

        Database::setup();
        OCClient::setup();
        AddressCache::setup();

        if ( verb == "create" && noun == "user" )
            createUser();
        else if ( verb == "delete" && noun == "user" )
            deleteUser();
        else if ( verb == "create" && noun == "mailbox" )
            createMailbox();
        else if ( verb == "delete" && noun == "mailbox" )
            deleteMailbox();
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
    else if ( verb == "list" || verb == "ls" ) {
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

    if ( r ) {
        Allocator::addEternal( r, "Event receiver" );
        Loop::start();
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


class Receiver
    : public EventHandler
{
public:
    Query * query;

    Receiver()
        : query( 0 )
    {
    }

    void waitFor( Query * q )
    {
        query = q;
    }

    virtual void process( Query * q )
    {
    }

    void execute()
    {
        process( query );
        if ( !query->done() )
            return;

        if ( query->failed() ) {
            if ( !Scope::current()->log()->disastersYet() )
                error( "Error: " + query->error() );
            status = -1;
        }

        Loop::shutdown();
    }
};


void showSchema()
{
    end();

    Database::setup();

    class SsReceiver : public Receiver {
    public:
        void process( Query * q )
        {
            const char * versions[] = {
                "", "", "0.91", "0.92", "0.92", "0.92 to 0.93",
                "0.93", "0.93", "0.94 to 0.95", "0.96", "0.97"
            };
            int nv = sizeof( versions ) / sizeof( versions[0] );

            Row * r = q->nextRow();
            if ( r ) {
                int rev = r->getInt( "revision" );

                String comment;
                if ( rev >= nv ) {
                    comment =
                        "too new for " +
                        Configuration::compiledIn( Configuration::Version );
                }
                else {
                    comment = versions[rev];
                    if ( rev == nv-1 )
                        comment.append( ", and perhaps later versions" );
                }

                if ( !comment.isEmpty() )
                    comment = " (" + comment + ")";
                printf( "%d%s\n", rev, comment.cstr() );
            }
        }
    };

    r = new SsReceiver;
    Query * q = new Query( "select revision from mailstore", r );
    r->waitFor( q );
    q->execute();
}


void upgradeSchema()
{
    end();

    Database::setup();

    r = new Receiver;
    Schema * s = new Schema( r, true );
    r->waitFor( s->result() );
    s->execute();
}


void createUser()
{
    parseOptions();
    String login = next();
    String passwd = next();
    String address = next();
    end();

    if ( login.isEmpty() || passwd.isEmpty() )
        error( "No login name and password supplied." );

    uint i = 0;
    while ( i < login.length() &&
            ( ( login[i] >= '0' && login[i] <= '9' ) ||
              ( login[i] >= 'a' && login[i] <= 'z' ) ||
              ( login[i] >= 'Z' && login[i] <= 'Z' ) ) )
        i++;
    if ( i < login.length() ||
         login == "anonymous" ||
         login == "anyone" ||
         login == "group" ||
         login == "user" )
    {
        error( "Invalid username: " + login );
    }

    User * u = new User;
    u->setLogin( login );
    u->setSecret( passwd );
    if ( !u->valid() )
        error( u->error() );
    if ( !address.isEmpty() ) {
        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );
        u->setAddress( p.addresses()->first() );
    }

    r = new Receiver;
    Mailbox::slurp( r );
    Query * q = u->create( r );
    if ( !q || q->failed() )
        error( q->error() );
    r->waitFor( q );
    u->execute();
}


void deleteUser()
{
    parseOptions();
    String login = next();
    end();

    if ( login.isEmpty() )
        error( "No login name supplied." );

    uint i = 0;
    while ( i < login.length() &&
            ( ( login[i] >= '0' && login[i] <= '9' ) ||
              ( login[i] >= 'a' && login[i] <= 'z' ) ||
              ( login[i] >= 'Z' && login[i] <= 'Z' ) ) )
        i++;
    if ( i < login.length() ||
         login == "anonymous" ||
         login == "anyone" ||
         login == "group" ||
         login == "user" )
    {
        error( "Invalid username: " + login );
    }

    User * u = new User;
    u->setLogin( login );

    r = new Receiver;
    Mailbox::slurp( r );
    Query * q = u->remove( r );
    if ( !q || q->failed() )
        error( q->error() );
    r->waitFor( q );
    u->execute();
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
    String pattern = next();
    end();

    Database::setup();

    class LuReceiver : public Receiver {
    public:
        void process( Query * q ) {
            while ( q->hasResults() ) {
                Row * r = q->nextRow();
                printf( "%-16s %s\n",
                        r->getString( "login" ).cstr(),
                        r->getString( "address" ).cstr() );
            }
        }
    };

    r = new LuReceiver;

    String s( "select login, localpart||'@'||domain as address "
              "from users u join addresses a on (u.address=a.id)" );
    if ( !pattern.isEmpty() )
        s.append( " where login like $1" );
    Query * q = new Query( s, r );
    if ( !pattern.isEmpty() ) {
        String p;
        uint i = 0;
        while ( pattern[i] ) {
            if ( pattern[i] == '*' )
                p.append( '%' );
            else if ( pattern[i] == '?' )
                p.append( '_' );
            else
                p.append( pattern[i] );
            i++;
        }
        q->bind( 1, p );
    }
    r->waitFor( q );
    q->execute();
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
            "    configuration may be abbreviated as cf.\n\n"
            "    Examples:\n\n"
            "      ms show configuration\n"
            "      ms show cf -p\n"
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
    else if ( a == "show" && b == "schema" ) {
        fprintf(
            stderr,
            "  show schema -- Display schema revision.\n\n"
            "    Synopsis: ms show schema\n\n"
            "    Displays the revision of the existing database schema.\n"
        );
    }
    else if ( a == "upgrade" && b == "schema" ) {
        fprintf(
            stderr,
            "  upgrade schema -- Upgrade the database schema.\n\n"
            "    Synopsis: ms update schema\n\n"
            "    Checks that the database schema is one that this version\n"
            "    of Mailstore is compatible with, and updates it if needed.\n"
        );
    }
    else if ( a == "create" && b == "user" ) {
        fprintf(
            stderr,
            "  create user -- Create a new user.\n\n"
            "    Synopsis: ms create user <login> <password> <e@ma.il>\n\n"
            "    Creates a new Mailstore user with the specified login\n"
            "    name, password, and email address.\n\n"
        );
    }
    else if ( a == "delete" && b == "user" ) {
        fprintf(
            stderr,
            "  delete user -- Delete a user.\n\n"
            "    Synopsis: ms create user <login>\n\n"
            "    Deletes the Mailstore user with the specified login.\n\n"
        );
    }
    else if ( a == "list" && b == "users" ) {
        fprintf(
            stderr,
            "  list users -- Display existing users.\n\n"
            "    Synopsis: ms list users [pattern]\n\n"
            "    Displays a list of users matching the specified shell\n"
            "    glob pattern. Without a pattern, all users are listed.\n\n"
            "    ls is an acceptable abbreviation for list.\n\n"
            "    Examples:\n\n"
            "      ms list users\n"
            "      ms ls users ab?cd*\n"
        );
    }
    else if ( a == "commands" ) {
        fprintf(
            stderr,
            "  Available ms commands:\n\n"
            "    start              -- Server management.\n"
            "    stop\n"
            "    restart\n\n"
            "    show status        -- Are the servers running?\n"
            "    show configuration -- Displays runtime configuration.\n"
            "    show build         -- Displays compile-time configuration.\n"
            "\n"
            "    show schema        -- Displays the existing schema revision.\n"
            "    upgrade schema     -- Upgrades an older schema to work with\n"
            "                          the current server.\n"
            "\n"
            "    list users         -- User and mailbox management.\n"
            "    create user\n"
            "    delete user\n"
            "    change password\n"
            "    create mailbox\n"
            "    delete mailbox\n\n"
            "  Use \"ms help command name\" for more specific help.\n"
        );
    }
    else {
        fprintf(
            stderr,
            "  ms -- A command-line interface to Oryx Mailstore.\n\n"
            "    Synopsis: %s <verb> <noun> [options] [arguments]\n\n"
            "    Use \"ms help commands\" for a list of commands.\n"
            "    Use \"ms help start\" for help with \"start\".\n",
            ms
        );
    }
}
